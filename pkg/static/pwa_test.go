package static

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func servePWATest(t *testing.T, handler http.HandlerFunc, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler(response, request)
	return response
}

func TestManifestNamesInstallableIconsAndColors(t *testing.T) {
	response := servePWATest(t, ServeManifest, nil)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/manifest+json" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("manifest response %d %v", response.Code, response.Header())
	}
	var manifest struct {
		Name, ShortName, StartURL, Scope, Display, ThemeColor, BackgroundColor string
		Icons                                                                  []struct{ Src, Sizes, Type, Purpose string }
	}
	raw := map[string]any{}
	if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"Name": raw["name"], "ShortName": raw["short_name"], "StartURL": raw["start_url"], "Scope": raw["scope"], "Display": raw["display"], "ThemeColor": raw["theme_color"], "BackgroundColor": raw["background_color"], "Icons": raw["icons"]})
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Name != "Veksel" || manifest.StartURL != "/app/" || manifest.Scope != "/app/" || manifest.Display != "standalone" || manifest.ThemeColor == "" || manifest.BackgroundColor == "" {
		t.Fatalf("manifest = %+v", manifest)
	}
	sizes := map[string]bool{}
	for _, icon := range manifest.Icons {
		// Every icon is an embedded, content-versioned asset.
		name := strings.TrimPrefix(strings.SplitN(icon.Src, "?v=", 2)[0], "/static/")
		if icon.Src != AssetURL(name) || !strings.Contains(icon.Src, "?v=") {
			t.Errorf("icon %s is not a versioned embedded asset", icon.Src)
		}
		if _, err := Content.ReadFile(name); err != nil {
			t.Errorf("icon %s: %v", icon.Src, err)
		}
		sizes[icon.Sizes+" "+icon.Purpose] = true
	}
	for _, want := range []string{"192x192 any", "512x512 any", "512x512 maskable"} {
		if !sizes[want] {
			t.Errorf("manifest lacks a %s icon", want)
		}
	}
}

func TestServiceWorkerIsVersionedByAssetsAndRevalidates(t *testing.T) {
	first := servePWATest(t, ServeServiceWorker, nil)
	headers := first.Header()
	if first.Code != http.StatusOK || headers.Get("Content-Type") != "text/javascript; charset=utf-8" || headers.Get("Cache-Control") != "no-cache" ||
		headers.Get("Service-Worker-Allowed") != "/app/" || !strings.Contains(headers.Get("Content-Security-Policy"), "default-src 'self'") || headers.Get("ETag") == "" {
		t.Fatalf("service worker response %d %v", first.Code, headers)
	}
	worker := first.Body.String()
	if strings.Contains(worker, "__VEKSEL_") {
		t.Fatal("service worker template placeholders were not filled")
	}
	if !strings.Contains(worker, "const VERSION = '"+PWAVersion()+"'") {
		t.Fatal("service worker does not carry the shell version")
	}
	// The precache list is exactly the versioned shell plus the offline page,
	// so an asset change yields new URLs, a new worker byte stream, and a new
	// cache name; old shell caches are deleted on activation.
	for _, name := range ShellAssets {
		if !strings.Contains(worker, `"`+AssetURL(name)+`"`) {
			t.Errorf("service worker does not precache %s", AssetURL(name))
		}
	}
	if !strings.Contains(worker, `"`+OfflinePath+"?v="+PWAVersion()+`"`) || !strings.Contains(worker, "key.startsWith('veksel-shell-') && key !== SHELL_CACHE") {
		t.Fatal("service worker does not version the offline page and prune old shells")
	}
	again := servePWATest(t, ServeServiceWorker, map[string]string{"If-None-Match": headers.Get("ETag")})
	if again.Code != http.StatusNotModified {
		t.Fatalf("worker revalidation status=%d", again.Code)
	}
	if len(PWAVersion()) != 16 {
		t.Fatalf("version %q", PWAVersion())
	}
}

// TestServiceWorkerNeverCachesAccountOrAdminData is a static check of the
// worker's request routing: API (including /api/v1/admin), DAV, and page
// HTML are never stored or served from cache, and nothing but the
// precached public shell is ever read from the cache.
func TestServiceWorkerNeverCachesAccountOrAdminData(t *testing.T) {
	source, err := pwaFiles.ReadFile("pwa/sw.js")
	if err != nil {
		t.Fatal(err)
	}
	worker := string(source)
	for _, required := range []string{
		"if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/dav/') || url.pathname === '/app/sw.js') return;",
		"if (url.origin !== self.location.origin) return;",
		"if (request.method !== 'GET') return;",
		"const cacheable = url => url.origin === self.location.origin && shellURLs.has(url.href);",
		"if (!cacheable(url)) return;",
		"event.respondWith(fetch(request).catch(() => caches.match(OFFLINE_URL)",
		"cache.addAll(SHELL_ASSETS)",
	} {
		if !strings.Contains(worker, required) {
			t.Errorf("service worker lacks %q", required)
		}
	}
	// The worker never writes a fetched response into any cache: the only
	// cache writes are the install-time precache of the public shell.
	for _, forbidden := range []string{"cache.put(", ".put(", "/api/v1/admin", "clone()"} {
		if strings.Contains(worker, forbidden) {
			t.Errorf("service worker contains %q", forbidden)
		}
	}
	// The API check precedes any respondWith, so no API request is answered by the worker.
	if strings.Index(worker, "url.pathname.startsWith('/api/')") > strings.Index(worker, "event.respondWith(") {
		t.Error("API requests are not excluded before the worker responds")
	}
	for _, asset := range ShellAssets {
		if strings.HasPrefix(asset, "/api") || strings.Contains(asset, "admin/") {
			t.Errorf("shell asset %s is not a public static file", asset)
		}
	}

	// The page writes the offline snapshot only for the signed-in person's own
	// folders, never while working as someone else, bounded, and clears it on
	// sign-out, session revocation, and account change.
	js := readAsset(t, "js/app.js")
	for _, required := range []string{
		"enabled=available&&sessionActorID===sessionSubjectID",
		"if(!enabled||!folder||folder.user_id!==sessionActorID)return;",
		"folders||[]).filter(folder=>folder.user_id===sessionActorID)",
		".slice(0,20)})", "text:text.slice(0,20000)", ".slice(0,50);write('agenda'",
		"new URL(form.action,location.origin).pathname!=='/app/logout'", "offlineSnapshot.clear().finally(()=>location.replace('/app/login'))",
		"if(entries.some(entry=>entry&&entry.owner!==sessionActorID))clear()",
		"navigator.serviceWorker.register('/app/sw.js',{scope:'/app/'})",
	} {
		if !strings.Contains(js, required) {
			t.Errorf("app.js lacks offline snapshot guard %q", required)
		}
	}
	offline := readAsset(t, "js/offline.js")
	if strings.Contains(offline, "fetch(") || strings.Contains(offline, "/api/") || strings.Contains(offline, "innerHTML") {
		t.Error("offline page must render only the local snapshot, without API calls or HTML injection")
	}
}

func TestOfflinePageServedWithStrictPolicy(t *testing.T) {
	response := servePWATest(t, ServeOfflinePage, nil)
	page := response.Body.String()
	policy := response.Header().Get("Content-Security-Policy")
	if response.Code != http.StatusOK || !strings.Contains(policy, "script-src 'self'") || !strings.Contains(policy, "frame-ancestors 'none'") || response.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("offline page response %d %v", response.Code, response.Header())
	}
	if strings.Contains(page, "__") || !strings.Contains(page, AssetURL("js/offline.js")) || !strings.Contains(page, AssetURL("css/app.css")) {
		t.Fatal("offline page does not reference the versioned shell")
	}
	if regexp.MustCompile(`<script>|\sstyle="|\son[a-z]+="`).MatchString(page) {
		t.Fatal("offline page uses inline script or style, which its policy forbids")
	}
}

func TestNotificationSoundAndIconsAreServed(t *testing.T) {
	for name, contentType := range map[string]string{"sounds/notify.wav": "audio/wav", "images/icon-192.png": "image/png", "images/apple-touch-icon.png": "image/png"} {
		response := get(t, AssetURL(name), nil)
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != contentType || response.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("%s: %d %v", name, response.Code, response.Header())
		}
	}
	if data, _ := Content.ReadFile("sounds/notify.wav"); len(data) > 32<<10 || string(data[:4]) != "RIFF" {
		t.Fatal("notification sound must be a small embedded WAV")
	}
}

func TestNotificationModuleContracts(t *testing.T) {
	js := readAsset(t, "js/app.js")
	for _, required := range []string{
		// One module: permission flow, per-type preferences, quiet hours, sound, cross-tab claims, click-to-open.
		"const notifier=(()=>{", "Notification.requestPermission()", "notificationPlan({kind,prefs:notificationPrefs,quiet:notificationQuiet(notificationPrefs,new Date(),displayPrefs.time_zone)",
		"localStorage.getItem('veksel.notifications.claimed')", "registration.showNotification(title,options)", "new Audio(body.dataset.notificationSound)",
		"event.data?.type==='veksel:notification-open'", "document.addEventListener('veksel:open-mail'",
		// All three sources go through it.
		"notifier.notify({kind:'meeting'", "notifier.notify({kind:'followup'", "notifier.notify({kind:'mail'",
		"detail.type!=='items.delivered'", "folder.special_use==='inbox'&&folder.user_id===sessionActorID", "body.dataset.viewingFolder=state.folder_id",
		"'/api/v1/user/notification-preferences'", "'/api/v1/user/display-preferences'",
	} {
		if !strings.Contains(js, required) {
			t.Errorf("app.js lacks %q", required)
		}
	}
	// Only the module constructs desktop notifications.
	if strings.Count(js, "new Notification(") != 1 || strings.Count(js, "Notification.requestPermission(") != 1 {
		t.Error("desktop notifications must be created and requested only by the notification module")
	}
}

// TestPreferenceAndNotificationHelpers runs the pure helpers under Node when it is installed.
func TestPreferenceAndNotificationHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	js := readAsset(t, "js/app.js")
	var declarations []string
	for _, name := range []string{"formatDisplayDate", "localDisplayPreferences", "notificationQuiet", "notificationPlan"} {
		match := regexp.MustCompile(`(?m)^\s*const ` + name + `=.*;$`).FindString(js)
		if match == "" {
			t.Fatalf("%s not found as a single-line declaration", name)
		}
		declarations = append(declarations, match)
	}
	script := "const displayPrefs={};\n" + strings.Join(declarations, "\n") + `
const assert=(ok,message)=>{if(!ok){console.error(message);process.exit(1)}};
const eq=(got,want,message)=>assert(got===want,message+': got '+JSON.stringify(got)+' want '+JSON.stringify(want));
const at=new Date(Date.UTC(2026,2,9,14,5));
const utc={time_zone:'UTC'};
eq(formatDisplayDate(at,{dateStyle:'medium',timeStyle:'short'},{...utc,date_order:'dmy',time_format:'24h'}),'9 Mar 2026, 14:05','day-month-year 24h');
eq(formatDisplayDate(at,{dateStyle:'medium',timeStyle:'short'},{...utc,date_order:'mdy',time_format:'12h'}).replace(/ /g,' '),'Mar 9, 2026, 2:05 PM','month-day-year 12h');
eq(formatDisplayDate(at,{year:'numeric',month:'2-digit',day:'2-digit'},{...utc,date_order:'ymd'}),'2026-03-09','numeric year-month-day');
eq(formatDisplayDate(at,{dateStyle:'medium',timeStyle:'short'},{...utc,date_order:'ymd',time_format:'24h'}),'2026 Mar 9, 14:05','year-month-day with time');
eq(formatDisplayDate(at,{hour:'2-digit',minute:'2-digit'},{time_zone:'Asia/Tokyo',time_format:'24h',date_order:'dmy'}),'23:05','account time zone');
eq(formatDisplayDate(at,{hour:'2-digit',minute:'2-digit'},{time_zone:'Asia/Tokyo',time_format:'24h',date_order:'dmy'},{local:true}),formatDisplayDate(at,{hour:'2-digit',minute:'2-digit'},{time_format:'24h',date_order:'dmy'}),'local ignores the account zone');
eq(formatDisplayDate(at,{hour:'2-digit',minute:'2-digit'},{time_zone:'Not/AZone',time_format:'24h',date_order:'dmy'}).length>0,true,'an unknown zone falls back');
eq(formatDisplayDate('',{dateStyle:'medium'},utc),'','empty value');
eq(formatDisplayDate('nonsense',{dateStyle:'medium'},utc),'','invalid value');
eq(formatDisplayDate(null,{dateStyle:'medium'},utc),'','null value');
const base={saved:false,reading_pane:'right',density:'compact',week_start:1,working_days:[1,2,3,4,5],work_start:'08:00',work_end:'17:00'};
const migrated=localDisplayPreferences(base,{reading_pane:'bottom',density:'comfortable',folder_id:'x'},{week_start:0,working_days:[3,1,1,9],work_start:'07:00',work_end:'15:30'});
eq(JSON.stringify(migrated),JSON.stringify({...base,saved:true,reading_pane:'bottom',density:'comfortable',week_start:0,working_days:[1,3],work_start:'07:00',work_end:'15:30'}),'migration adopts local choices');
eq(JSON.stringify(localDisplayPreferences(base,{reading_pane:'left',density:'huge'},{week_start:9,working_days:[],work_start:'18:00',work_end:'09:00'})),JSON.stringify({...base,saved:true}),'migration ignores invalid local values');
const quiet={quiet_hours:true,quiet_start:'22:00',quiet_end:'07:00'};
eq(notificationQuiet(quiet,new Date(Date.UTC(2026,0,1,23,0)),'UTC'),true,'overnight quiet hours late');
eq(notificationQuiet(quiet,new Date(Date.UTC(2026,0,1,6,59)),'UTC'),true,'overnight quiet hours early');
eq(notificationQuiet(quiet,new Date(Date.UTC(2026,0,1,7,0)),'UTC'),false,'quiet hours end exclusive');
eq(notificationQuiet(quiet,new Date(Date.UTC(2026,0,1,12,0)),'UTC'),false,'daytime');
eq(notificationQuiet({...quiet,quiet_hours:false},new Date(Date.UTC(2026,0,1,23,0)),'UTC'),false,'disabled');
eq(notificationQuiet({quiet_hours:true,quiet_start:'12:00',quiet_end:'13:00'},new Date(Date.UTC(2026,0,1,12,30)),'UTC'),true,'same-day window');
eq(notificationQuiet(quiet,new Date(Date.UTC(2026,0,1,13,30)),'Asia/Tokyo'),true,'quiet hours follow the account zone (22:30 in Tokyo)');
const prefs={new_mail:true,favorites:false,meetings:true,follow_ups:false,sound:true};
const mail=extra=>notificationPlan({kind:'mail',prefs,folderID:'inbox',inboxIDs:['inbox'],favoriteIDs:['fav'],...extra});
eq(JSON.stringify(mail({focused:false})),JSON.stringify({toast:false,desktop:true,sound:true}),'background tab gets a desktop alert');
eq(mail({focused:true,viewingFolderID:'inbox'}),null,'never for the viewed folder in a focused tab');
eq(JSON.stringify(mail({focused:true,viewingFolderID:'archive'})),JSON.stringify({toast:true,desktop:false,sound:true}),'focused tab elsewhere toasts');
eq(JSON.stringify(mail({focused:false,viewingFolderID:'inbox'})),JSON.stringify({toast:false,desktop:true,sound:true}),'viewed folder in an unfocused tab still notifies');
eq(mail({folderID:'fav'}),null,'favorites are off');
eq(JSON.stringify(notificationPlan({kind:'mail',prefs:{...prefs,favorites:true},folderID:'fav',inboxIDs:['inbox'],favoriteIDs:['fav']})),JSON.stringify({toast:false,desktop:true,sound:true}),'favorites when chosen');
eq(mail({folderID:'junk'}),null,'other folders never notify');
eq(notificationPlan({kind:'mail',prefs:{...prefs,new_mail:false},folderID:'inbox',inboxIDs:['inbox']}),null,'new mail off');
eq(JSON.stringify(mail({quiet:true})),JSON.stringify({toast:false,desktop:false,sound:false}),'quiet hours silence desktop and sound');
eq(JSON.stringify(notificationPlan({kind:'meeting',prefs,focused:true})),JSON.stringify({toast:true,desktop:false,sound:true}),'meeting reminder in a focused tab');
eq(notificationPlan({kind:'followup',prefs}),null,'follow-ups off');
eq(notificationPlan({kind:'unknown',prefs}),null,'unknown kinds');
`
	dir := t.TempDir()
	path := filepath.Join(dir, "preferences.js")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, node, path).CombinedOutput(); err != nil {
		t.Fatalf("node helpers failed: %v\n%s", err, output)
	}
}
