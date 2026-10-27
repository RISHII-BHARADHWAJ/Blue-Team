"""Real browser acceptance against disposable Compose, with screenshot artifacts."""
import json, pathlib, subprocess
from playwright.sync_api import sync_playwright, expect
out=pathlib.Path('visual-artifacts');out.mkdir(exist_ok=True)
f=json.loads(subprocess.check_output(['docker','compose','exec','-T','-u','www-data','-e','SOAR_INTEGRATION_TEST=1','web','php','tests/ui_fixture.php'],text=True))
base='http://localhost:8080/'
with sync_playwright() as p:
 browser=p.chromium.launch()
 context=browser.new_context(viewport={'width':1440,'height':1000},reduced_motion='reduce')
 page=context.new_page()
 page.goto(base+'login.php');page.screenshot(path=str(out/'login-desktop.png'),full_page=True)
 assert page.locator('label[for="username"]').is_visible()
 page.set_viewport_size({'width':390,'height':844});page.screenshot(path=str(out/'login-mobile.png'),full_page=True)
 assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 2')
 page.set_viewport_size({'width':1440,'height':1000})
 page.get_by_role('button',name='Switch to dark mode').click()
 page.reload();assert page.locator('html').get_attribute('data-theme')=='dark'
 page.screenshot(path=str(out/'login-dark-mobile.png'),full_page=True)
 page.get_by_role('button',name='Switch to light mode').click()
 context.add_cookies([{'name':'CYBERTECH_SECURE_SESSION','value':f['session'],'url':base}])
 routes=['soc.php','events.php','sources.php','dashboard.php','incidents.php','detections.php','threat-intel.php','feeds.php','notifications.php','audit.php','demo.php','incident-new.php','control_plane/index.php','terminal.php']
 routes += [x+'?id='+str(f['case_id']) for x in ['incidents.php','incident-risk.php','incident-iocs.php','incident-playbooks.php','incident-evidence.php','incident-linked-evidence.php','incident-timeline.php','incident-report.php']]
 failures=[]
 for i,route in enumerate(routes):
  response=page.goto(base+route,wait_until='domcontentloaded');page.wait_for_timeout(400)
  name=route.split('?')[0].replace('/','-').replace('.php','')+('-detail' if '?' in route else '')
  try:
   assert response.status==200, f'HTTP {response.status}'
   assert page.locator('.tp-rail').is_visible(),'shared navigation missing'
   assert page.locator('.tp-rail [aria-current="page"]').count()==1,'active navigation missing'
   assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 2'),'horizontal page overflow'
  except Exception as e:failures.append(f'{route}: {e}')
  page.screenshot(path=str(out/(name+'-desktop.png')),full_page=True)
 # Mobile navigation and layout across every workspace.
 page.set_viewport_size({'width':390,'height':844})
 for route in routes:
  page.goto(base+route,wait_until='domcontentloaded');page.wait_for_timeout(200)
  name=route.split('?')[0].replace('/','-').replace('.php','')+('-detail' if '?' in route else '')
  page.screenshot(path=str(out/(name+'-mobile.png')),full_page=True)
  if not page.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 2'):failures.append(route+': mobile overflow')
 page.goto(base+'soc.php');page.get_by_role('button',name='Toggle navigation').click()
 assert page.get_by_role('button',name='Toggle navigation').get_attribute('aria-expanded')=='true'
 page.locator('.tp-rail').get_by_role('link',name='Cases',exact=True).click();assert 'incidents.php' in page.url
 page.goto(base+'incident-new.php');page.locator('#case-title').fill('Browser acceptance report');page.locator('#case-report').fill('Synthetic browser check in the disposable CI environment.');page.get_by_role('button',name='Create case and save report').click();page.wait_for_url('**/incidents.php?**')
 assert page.locator('#details').get_by_text('Browser acceptance report',exact=False).count()>0
 # Real repeated demo batches, then stop and prove no extra request is scheduled.
 page.goto(base+'demo.php');page.locator('#stream-interval').select_option('10')
 page.locator('#stream-start').click()
 expect(page.locator('#stream-results li')).to_have_count(2,timeout=25000)
 page.locator('#stream-stop').click()
 page.wait_for_timeout(11500)
 assert page.locator('#stream-results li').count()==2
 assert page.locator('#stream-start').is_enabled()
 page.screenshot(path=str(out/'demo-stream-mobile.png'),full_page=True)
 demo_link=page.locator('#stream-results a').first.get_attribute('href')
 page.goto(base+demo_link)
 assert page.get_by_text('SIMULATED TEST DATA',exact=True).is_visible()
 assert page.get_by_role('link',name='Open simulated incident').is_visible()
 # Theme choice persists through navigation and covers every route at both widths.
 page.goto(base+'soc.php');page.get_by_role('button',name='Switch to dark mode').click()
 for width,label in [(1440,'desktop'),(390,'mobile')]:
  page.set_viewport_size({'width':width,'height':1000 if width==1440 else 844})
  for route in routes:
   page.goto(base+route,wait_until='domcontentloaded')
   assert page.locator('html').get_attribute('data-theme')=='dark'
   assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 2'),route
   name=route.split('?')[0].replace('/','-').replace('.php','')+('-detail' if '?' in route else '')
   page.screenshot(path=str(out/(name+'-dark-'+label+'.png')),full_page=True)
 page.get_by_role('button',name='Switch to light mode').click();page.reload()
 assert page.locator('html').get_attribute('data-theme')=='light'
 # A fresh browser follows the OS preference before any explicit selection.
 fresh=browser.new_context(color_scheme='dark')
 fresh_page=fresh.new_page();fresh_page.goto(base+'login.php')
 assert fresh_page.locator('html').get_attribute('data-theme')=='dark'
 fresh.close()
 page.goto(base+'incident-report.php?id='+str(f['case_id']));page.emulate_media(media='print');page.pdf(path=str(out/'case-report.pdf'),format='A4',print_background=True)
 (out/'results.json').write_text(json.dumps({'routes':routes,'failures':failures},indent=2))
 # Terminal payload must render as text without adding executable DOM nodes.
 page.goto(base+'terminal.php')
 terminal_input=page.locator('input').first
 terminal_input.fill('<img src=x onerror="window.securityProbe=1">')
 terminal_input.press('Enter')
 page.wait_for_timeout(100)
 assert page.evaluate('window.securityProbe === undefined')
 assert page.locator('img[onerror]').count()==0
 browser.close()
 assert not failures,'\n'.join(failures)
 print('PASS: desktop/mobile layout, shared navigation, intake submission and printable report')
