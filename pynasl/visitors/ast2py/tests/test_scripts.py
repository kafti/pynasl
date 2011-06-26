#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------
"""Translator tests using unified_diff"""

import unittest
import os
import sys
from difflib import unified_diff

from pynasl.visitors.ast2py.translator import ast2py_str


class Test(unittest.TestCase):

    def generate_script_str(self, script_name):
        return ast2py_str(os.path.join(os.environ['KAFTI_NASLSCRIPTS_PATH'], script_name))

    def check(self, sample_str, script_str):
        has_diffs = False
        for line in unified_diff(sample_str.splitlines(True), script_str.splitlines(True), 'sample', 'generated'):
            has_diffs = True
            sys.stdout.write(line)
        
        self.assertFalse(has_diffs)

    def test_secpod_apache_detect(self):
        sample = """from nasllibs.core import *
from nasllibs.scriptmetadata import *
from nasllibs.http_func import *


def get_metadata():
    metadata = ScriptMetadata()
    metadata.script_id = 900498
    metadata.script_version = "Revision: 1.0 "
    metadata.set_script_tag(name="risk_factor", value="None")
    metadata.script_name = "Apache Web ServerVersion Detection"
    desc = \"""
      Overview : This script finds the running Apache Version and saves the
      result in KB.
    
      Risk factor : None\"""
    metadata.script_description = desc
    metadata.script_family = "Service detection"
    metadata.script_category = ACT_TYPES.ACT_GATHER_INFO
    metadata.script_copyright = "Copyright (C) 2009 SecPod"
    metadata.script_summary = "Set Version of Apache Web Server in KB"
    metadata.script_dependencies = "find_service.nes"
    metadata.set_script_require_ports("Services/www", 80)
    
    return metadata
    

def main():
    
    port = get_http_port(default=80)
    
    if not get_port_state(port):
        return
        
    banner = get_http_banner(port=port)
    
    if "Apache" not in banner:
        return
        
    apacheVer = eregmatch(pattern=r"Server: Apache/([0-9]\.[0-9]+\.[0-9][0-9]?)", string=banner)
    
    if apacheVer[1] != None:
        set_kb_item(name="www/" + str(port) + "/Apache", value=apacheVer[1])
        security_note(data="Apache Web Server version " + str(apacheVer[1]) + " was detected on the host")
        
if __name__ == '__main__':
    import sys
    from nasllibs.core.context import context

    try:
        import _settings
    except ImportError:
        pass

    context.from_argv(sys.argv)
    main()
"""
    
        script_str = self.generate_script_str("secpod_apache_detect.nasl")
        self.check(sample, script_str)

    def test_http_version(self):
        sample = r'''from nasllibs.core import *
from nasllibs.scriptmetadata import *
from nasllibs.http_func import *


def get_metadata():
    metadata = ScriptMetadata()
    metadata.script_id = 10107
    metadata.script_version = "$Revision: 7515 $"
    metadata.set_script_tag(name="risk_factor", value="None")
    name = "HTTP Server type and version"
    metadata.script_name = name
    desc = """This detects the HTTP Server's type and version.
    
    Solution: Configure your server to use an alternate name like 
        'Wintendo httpD w/Dotmatrix display'
    Be sure to remove common logos like apache_pb.gif.
    With Apache, you can set the directive 'ServerTokens Prod' to limit
    the information emanating from the server in its response headers.
    
    Risk factor : None"""
    metadata.script_description = desc
    summary = "HTTP Server type and version"
    metadata.script_summary = summary
    metadata.script_category = ACT_TYPES.ACT_GATHER_INFO
    metadata.script_copyright = "This script is Copyright (C) 2000 H. Scholz & Contributors"
    family = "General"
    metadata.script_family = family
    metadata.script_dependencie = ["find_service.nes", "http_login.nasl", "httpver.nasl", "no404.nasl", "www_fingerprinting_hmap.nasl", "webmin.nasl", "embedded_web_server_detect.nasl"]
    metadata.set_script_require_ports("Services/www", 80)
    
    return metadata
    

def main():
    
    def get_apache_version():    
        req = http_get(item="/nonexistent_please_dont_exist", port=port)
        soc = http_open_socket(port)
        
        if not soc:
            return None
        
        send(soc=soc, data=req)
        r = egrep(pattern="<ADDRESS>.*</ADDRESS>", string=http_recv(soc=soc))
        http_close_socket(soc)
        
        if not r:
            return None
        
        v = ereg_replace(string=r, pattern="<ADDRESS>(Apache/[^ ]*).*", replace=r"\1")
        
        if r == v:
            return None
        
        else:
            return v
        
        
    def get_domino_version():    
        req = http_get(item="/nonexistentdb.nsf", port=port)
        soc = http_open_socket(port)
        
        if not soc:
            return None
        
        send(soc=soc, data=req)
        r = egrep(pattern=".*Lotus-Domino .?Release.*", string=http_recv(soc=soc))
        http_close_socket(soc)
        v = None
        
        if r != None:
            v = ereg_replace(pattern=".*Lotus-Domino .?Release ([^ <]*).*", replace=r"Lotus-Domino/\1", string=r)
        
        if r == None or v == r:
            
            if get_port_state(25):
                soc = open_sock_tcp(25)
                
                if soc:
                    r = recv_line(soc=soc, length=4096)
                    close(soc)
                    v = ereg_replace(pattern=".*Lotus Domino .?Release ([^)]*).*", replace=r"Lotus-Domino/\1", string=r)
                    
                    if v == r:
                        return None
                    
                    else:
                        return v
                    
                    
                
            return None
            
            
        else:
            return v
        
        
    port = get_http_port(default=80)
    
    if get_port_state(port):
        soctcp80 = http_open_socket(port)
        
        if soctcp80:
            data = http_get(item="/", port=port)
            resultsend = send(soc=soctcp80, data=data)
            resultrecv = http_recv_headers2(soc=soctcp80)
            
            if "Server: " in resultrecv:
                svrline = egrep(pattern="^(DAAP-)?Server:", string=resultrecv)
                svr = ereg_replace(pattern=".*Server: (.*)$", string=svrline, replace=r"\1")
                report = nasl_string("The remote web server type is :\n\n")
                
                if "Apache" in svr:
                    
                    if "Apache/" in svr:
                        report = str(report) + str(svr) + nasl_string("\n\nSolution : You can set the directive 'ServerTokens Prod' to limit\nthe information emanating from the server in its response headers.")
                    else:
                        svr2 = get_apache_version()
                        
                        if svr2 != None:
                            report = str(report) + str(svr2) + nasl_string("\n\nThe 'ServerTokens' directive is set to ProductOnly\n", "however we could determine that the version of the remote\n", "server by requesting a non-existent page.\n")
                            svrline = nasl_string("Server: ", svr2, r"\r\n")
                            replace_kb_item(name=nasl_string("www/real_banner/", port), value=svrline)
                            
                            if not get_kb_item("www/banner/" + str(port)):
                                replace_kb_item(name="www/banner/" + str(port), value=svrline)
                            
                        else:
                            report = str(report) + str(svr) + nasl_string("\nand the 'ServerTokens' directive is ProductOnly\nApache does not permit to hide the server type.\n")
                        
                    
                else:
                    
                    if "Lotus-Domino" in svr:
                        
                        if egrep(pattern=r"Lotus-Domino/[1-9]\.[0-9]", string=svr):
                            report = report + svr
                        else:
                            svr2 = get_domino_version()
                            
                            if svr2 != None:
                                report = str(report) + str(svr2) + nasl_string("\n\nThe product version is hidden but we could determine it by\n", "requesting a non-existent .nsf file or connecting to port 25\n")
                                svrline = nasl_string("Server: ", svr2, r"\r\n")
                                replace_kb_item(name=nasl_string("www/real_banner/", port), value=svrline)
                                
                                if not get_kb_item("www/banner/" + str(port)):
                                    replace_kb_item(name="www/banner/" + str(port), value=svrline)
                                
                            else:
                                report = report + svr
                            
                        
                    else:
                        report = report + svr
                        
                    
                security_note(port=port, data=report)
                
                if egrep(pattern="^Server:.*Domino.*", string=svrline):
                    set_kb_item(name="www/domino", value=True)
                
                if egrep(pattern="^Server:.*Apache.*", string=svrline):
                    set_kb_item(name="www/apache", value=True)
                
                if egrep(pattern="^Server:.*Apache.* Tomcat/", string=svrline, icase=1):
                    set_kb_item(name="www/tomcat", value=True)
                
                if egrep(pattern="^Server:.*Microsoft.*", string=svrline):
                    set_kb_item(name="www/iis", value=True)
                
                if egrep(pattern="^Server:.*Zope.*", string=svrline):
                    set_kb_item(name="www/zope", value=True)
                
                if egrep(pattern="^Server:.*CERN.*", string=svrline):
                    set_kb_item(name="www/cern", value=True)
                
                if egrep(pattern="^Server:.*Zeus.*", string=svrline):
                    set_kb_item(name="www/zeus", value=True)
                
                if egrep(pattern="^Server:.*WebSitePro.*", string=svrline):
                    set_kb_item(name="www/websitepro", value=True)
                
                if egrep(pattern="^Server:.*NCSA.*", string=svrline):
                    set_kb_item(name="www/ncsa", value=True)
                
                if egrep(pattern="^Server:.*Netscape-Enterprise.*", string=svrline):
                    set_kb_item(name="www/iplanet", value=True)
                
                if egrep(pattern="^Server:.*Netscape-Administrator.*", string=svrline):
                    set_kb_item(name="www/iplanet", value=True)
                
                if egrep(pattern="^Server:.*thttpd/.*", string=svrline):
                    set_kb_item(name="www/thttpd", value=True)
                
                if egrep(pattern="^Server:.*WDaemon.*", string=svrline):
                    set_kb_item(name="www/wdaemon", value=True)
                
                if egrep(pattern="^Server:.*SAMBAR.*", string=svrline):
                    set_kb_item(name="www/sambar", value=True)
                
                if egrep(pattern="^Server:.*IBM-HTTP-Server.*", string=svrline):
                    set_kb_item(name="www/ibm-http", value=True)
                
                if egrep(pattern="^Server:.*Alchemy.*", string=svrline):
                    set_kb_item(name="www/alchemy", value=True)
                
                if egrep(pattern="^Server:.*Rapidsite/Apa.*", string=svrline):
                    set_kb_item(name="www/apache", value=True)
                
                if egrep(pattern="^Server:.*Statistics Server.*", string=svrline):
                    set_kb_item(name="www/statistics-server", value=True)
                
                if egrep(pattern="^Server:.*CommuniGatePro.*", string=svrline):
                    set_kb_item(name="www/communigatepro", value=True)
                
                if egrep(pattern="^Server:.*Savant.*", string=svrline):
                    set_kb_item(name="www/savant", value=True)
                
                if egrep(pattern="^Server:.*StWeb.*", string=svrline):
                    set_kb_item(name="www/stweb", value=True)
                
                if egrep(pattern="^Server:.*StWeb.*", string=svrline):
                    set_kb_item(name="www/apache", value=True)
                
                if egrep(pattern="^Server:.*Oracle HTTP Server.*", string=svrline):
                    set_kb_item(name="www/OracleApache", value=True)
                
                if egrep(pattern="^Server:.*Oracle HTTP Server.*", string=svrline):
                    set_kb_item(name="www/apache", value=True)
                
                if egrep(pattern="^Server:.*Stronghold.*", string=svrline):
                    set_kb_item(name="www/stronghold", value=True)
                
                if egrep(pattern="^Server:.*Stronghold.*", string=svrline):
                    set_kb_item(name="www/apache", value=True)
                
                if egrep(pattern="^Server:.*MiniServ.*", string=svrline):
                    set_kb_item(name="www/miniserv", value=True)
                
                if egrep(pattern="^Server:.*vqServer.*", string=svrline):
                    set_kb_item(name="www/vqserver", value=True)
                
                if egrep(pattern="^Server:.*VisualRoute.*", string=svrline):
                    set_kb_item(name="www/visualroute", value=True)
                
                if egrep(pattern="^Server:.*Squid.*", string=svrline):
                    set_kb_item(name="www/squid", value=True)
                
                if egrep(pattern="^Server:.*OmniHTTPd.*", string=svrline):
                    set_kb_item(name="www/omnihttpd", value=True)
                
                if egrep(pattern="^Server:.*linuxconf.*", string=svrline):
                    set_kb_item(name="www/linuxconf", value=True)
                
                if egrep(pattern="^Server:.*CompaqHTTPServer.*", string=svrline):
                    set_kb_item(name="www/compaq", value=True)
                
                if egrep(pattern="^Server:.*WebSTAR.*", string=svrline):
                    set_kb_item(name="www/webstar", value=True)
                
                if egrep(pattern="^Server:.*AppleShareIP.*", string=svrline):
                    set_kb_item(name="www/appleshareip", value=True)
                
                if egrep(pattern="^Server:.*Jigsaw.*", string=svrline):
                    set_kb_item(name="www/jigsaw", value=True)
                
                if egrep(pattern="^Server:.*Resin.*", string=svrline):
                    set_kb_item(name="www/resin", value=True)
                
                if egrep(pattern="^Server:.*AOLserver.*", string=svrline):
                    set_kb_item(name="www/aolserver", value=True)
                
                if egrep(pattern="^Server:.*IdeaWebServer.*", string=svrline):
                    set_kb_item(name="www/ideawebserver", value=True)
                
                if egrep(pattern="^Server:.*FileMakerPro.*", string=svrline):
                    set_kb_item(name="www/filemakerpro", value=True)
                
                if egrep(pattern="^Server:.*NetWare-Enterprise-Web-Server.*", string=svrline):
                    set_kb_item(name="www/netware", value=True)
                
                if egrep(pattern="^Server:.*Roxen.*", string=svrline):
                    set_kb_item(name="www/roxen", value=True)
                
                if egrep(pattern="^Server:.*SimpleServer:WWW.*", string=svrline):
                    set_kb_item(name="www/simpleserver", value=True)
                
                if egrep(pattern="^Server:.*Allegro-Software-RomPager.*", string=svrline):
                    set_kb_item(name="www/allegro", value=True)
                
                if egrep(pattern="^Server:.*GoAhead-Webs.*", string=svrline):
                    set_kb_item(name="www/goahead", value=True)
                
                if egrep(pattern="^Server:.*Xitami.*", string=svrline):
                    set_kb_item(name="www/xitami", value=True)
                
                if egrep(pattern="^Server:.*EmWeb.*", string=svrline):
                    set_kb_item(name="www/emweb", value=True)
                
                if egrep(pattern="^Server:.*Ipswitch-IMail.*", string=svrline):
                    set_kb_item(name="www/ipswitch-imail", value=True)
                
                if egrep(pattern="^Server:.*Netscape-FastTrack.*", string=svrline):
                    set_kb_item(name="www/netscape-fasttrack", value=True)
                
                if egrep(pattern="^Server:.*AkamaiGHost.*", string=svrline):
                    set_kb_item(name="www/akamaighost", value=True)
                
                if egrep(pattern="^Server:.*[aA]libaba.*", string=svrline):
                    set_kb_item(name="www/alibaba", value=True)
                
                if egrep(pattern="^Server:.*tigershark.*", string=svrline):
                    set_kb_item(name="www/tigershark", value=True)
                
                if egrep(pattern="^Server:.*Netscape-Commerce.*", string=svrline):
                    set_kb_item(name="www/netscape-commerce", value=True)
                
                if egrep(pattern="^Server:.*Oracle_Web_listener.*", string=svrline):
                    set_kb_item(name="www/oracle-web-listener", value=True)
                
                if egrep(pattern="^Server:.*Caudium.*", string=svrline):
                    set_kb_item(name="www/caudium", value=True)
                
                if egrep(pattern="^Server:.*Communique.*", string=svrline):
                    set_kb_item(name="www/communique", value=True)
                
                if egrep(pattern="^Server:.*Cougar.*", string=svrline):
                    set_kb_item(name="www/cougar", value=True)
                
                if egrep(pattern="^Server:.*FirstClass.*", string=svrline):
                    set_kb_item(name="www/firstclass", value=True)
                
                if egrep(pattern="^Server:.*NetCache.*", string=svrline):
                    set_kb_item(name="www/netcache", value=True)
                
                if egrep(pattern="^Server:.*AnWeb.*", string=svrline):
                    set_kb_item(name="www/anweb", value=True)
                
                if egrep(pattern="^Server:.*Pi3Web.*", string=svrline):
                    set_kb_item(name="www/pi3web", value=True)
                
                if egrep(pattern="^Server:.*TUX.*", string=svrline):
                    set_kb_item(name="www/tux", value=True)
                
                if egrep(pattern="^Server:.*Abyss.*", string=svrline):
                    set_kb_item(name="www/abyss", value=True)
                
                if egrep(pattern="^Server:.*BadBlue.*", string=svrline):
                    set_kb_item(name="www/badblue", value=True)
                
                if egrep(pattern="^Server:.*WebServer 4 Everyone.*", string=svrline):
                    set_kb_item(name="www/webserver4everyone", value=True)
                
                if egrep(pattern="^Server:.*KeyFocus Web Server.*", string=svrline):
                    set_kb_item(name="www/KFWebServer", value=True)
                
                if egrep(pattern="^Server:.*Jetty.*", string=svrline):
                    set_kb_item(name="www/jetty", value=True)
                
                if egrep(pattern="^Server:.*bkhttp/.*", string=svrline):
                    set_kb_item(name="www/BitKeeper", value=True)
                
                if egrep(pattern="^Server:.*CUPS/.*", string=svrline):
                    set_kb_item(name="www/cups", value=True)
                
                if egrep(pattern="^Server:.*WebLogic.*", string=svrline):
                    set_kb_item(name="www/weblogic", value=True)
                
                if egrep(pattern="^Server:.*Novell-HTTP-Server.*", string=svrline):
                    set_kb_item(name="www/novell", value=True)
                
                if egrep(pattern="^Server:.*theServer/.*", string=svrline):
                    set_kb_item(name="www/theserver", value=True)
                
                if egrep(pattern="^Server:.*WWW File Share.*", string=svrline):
                    set_kb_item(name="www/wwwfileshare", value=True)
                
            close(soctcp80)
            
        
if __name__ == '__main__':
    import sys
    from nasllibs.core.context import context

    try:
        import _settings
    except ImportError:
        pass

    context.from_argv(sys.argv)
    main()
'''
        script_str = self.generate_script_str("http_version.nasl")
        self.check(sample, script_str)

    def test_secpod_apache_mod_proxy_ajp_info_disc_vuln(self):
        sample = '''from nasllibs.core import *
from nasllibs.scriptmetadata import *
from nasllibs.http_func import *
from nasllibs.version_func import *


def get_metadata():
    metadata = ScriptMetadata()
    metadata.script_id = 900499
    metadata.script_version = "$Revision: 1.0 $"
    metadata.set_script_tag(name="cvss_base", value="5.0")
    metadata.set_script_tag(name="risk_factor", value="Medium")
    metadata.script_cve_id = "CVE-2009-1191"
    metadata.script_bugtraq_id = 34663
    metadata.script_name = "Apache mod_proxy_ajp Information Disclosure Vulnerability"
    desc = """
    
      Overview: This host is running Apache Web Server and is prone to
      Information Disclosure Vulnerability.
    
      Vulnerability Insight:
      This flaw is caused due to an error in 'mod_proxy_ajp' when handling
      improperly malformed POST requests.
    
      Impact:
      Successful exploitation will let the attacker craft a special HTTP POST
      request and gain sensitive information about the web server.
    
      Impact level: Application
    
      Affected Software/OS:
      Apache HTTP Version 2.2.11
    
      Workaround:
      Update mod_proxy_ajp.c through SVN Repository (Revision 767089)
      http://www.apache.org/dist/httpd/patches/apply_to_2.2.11/PR46949.diff
    
      Fix: Upgrade to Apache HTTP Version 2.2.15 or later
      For further updates refer, http://httpd.apache.org/download.cgi
    
      References:
      http://secunia.com/advisories/34827
      http://xforce.iss.net/xforce/xfdb/50059
      http://svn.apache.org/viewvc/httpd/httpd/trunk/CHANGES?r1=766938&r2=767089
    
      CVSS Score:
        CVSS Base Score     : 5.0 (AV:N/AC:L/Au:NR/C:P/I:N/A:N)
        CVSS Temporal Score : 4.0
      Risk factor: Medium"""
    metadata.script_description = desc
    metadata.script_summary = "Check for Apache Web Server version"
    metadata.script_category = ACT_TYPES.ACT_GATHER_INFO
    metadata.script_copyright = "Copyright (C) 2009 SecPod"
    metadata.script_family = "Web application abuses"
    metadata.script_dependencies = "http_version.nasl", "secpod_apache_detect.nasl"
    metadata.set_script_require_ports("Services/www", 80)
    
    return metadata
    

def main():
    
    
    httpdPort = get_http_port(default=80)
    
    if not httpdPort:
        return
        
    version = get_kb_item("www/" + str(httpdPort) + "/Apache")
    
    if version != None:
        
        if version_is_less_equal(version=version, test_version="2.2.11"):
            security_warning(httpdPort)
            
        
if __name__ == '__main__':
    import sys
    from nasllibs.core.context import context

    try:
        import _settings
    except ImportError:
        pass

    context.from_argv(sys.argv)
    main()
'''
    
        script_str = self.generate_script_str("secpod_apache_mod_proxy_ajp_info_disc_vuln.nasl")
        self.check(sample, script_str)


if __name__ == "__main__":
    unittest.main()
