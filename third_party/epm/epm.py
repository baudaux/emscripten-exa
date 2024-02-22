#!/usr/bin/python3
 
import argparse
import json
import tarfile
import requests
import base64
import os
import os.path
import tempfile
import time
from getpass import getpass

def search_package(package):

    print("Search package "+package+" in exaequOS store")

    res = requests.get('https://exaequOS.com/find_in_store.php?lib=1&s='+base64.b64encode(package.encode('ascii')).decode('ascii'))

    r = res.json()

    print(str(r["nb_results"])+" package(s) found\n")

    for pkg in r["apps"]:
        print(pkg["pkg"]+ " - " + pkg["version"] + " - " + pkg["desc"]+ " - by " + pkg["user"])

    print("----------")
    
def search_fun(packages):

    for pkg in packages:
        search_package(pkg)

def update_pkg_list(pkg):

    pkg_list = "pkg_list.json"

    if os.path.isfile(pkg_list):
        f = open(pkg_list, "r+")
        content = f.read()
        obj = json.loads(content)
        f.seek(0)

    else:
        f = open(pkg_list, "w")
        
        obj = {}
        obj["packages"] = {}

    obj["packages"][pkg["name"]] = pkg["version"]

    json.dump(obj, f)
    f.close()
    
    print("Package "+pkg["name"]+" ("+pkg["version"]+") installed");

def install_package(package):

    res = requests.get('https://exaequOS.com/get_pkg.php?lib=1&s='+base64.b64encode(package.encode('ascii')).decode('ascii'))

    f = tempfile.NamedTemporaryFile(delete=False)
    
    f.write(res.content)
    f.close();

    tmpdir = "exapkgs/tmp"+str(time.time())
    
    with tarfile.open(f.name, 'r') as tar:
        tar.extractall(tmpdir)

    with open(tmpdir+"/pkginfo.exa", "r") as infile:
        content = infile.read()
        obj = json.loads(content)

        name = obj["pkg"]["name"]

    inst_dir = os.getcwd()+"/exapkgs/"+name
    
    for pcfile in os.listdir(tmpdir+"/pkgconfig"):
        if pcfile.endswith(".pc"):
            with open(tmpdir+"/pkgconfig/"+pcfile, 'r+') as pc:
                datain = pc.read()
                dataout = datain.replace("@INST_DIR@", inst_dir)
                pc.seek(0)
                pc.write(dataout)
                pc.truncate()
        
    try:
        os.system("cp "+tmpdir+"/pkgconfig/*.pc exapkgs/pkgconfigs/")
        os.rename("exapkgs/"+name, tempfile.gettempdir()+"/"+name+str(time.time()))
    except:
        pass
    
    os.rename(tmpdir, "exapkgs/"+name)
    
    update_pkg_list({"name": name, "version": obj["pkg"]["version"]})

def install_fun(packages):

    try:
        os.mkdir("exapkgs")
        os.mkdir("exapkgs/pkgconfigs")
    except:
        pass

    if len(packages) == 0:

        pkg_list = "pkg_list.json"

        with open(pkg_list, "r") as infile:
            content = infile.read()
            obj = json.loads(content)

            packages = list(obj["packages"].keys())
    
    for pkg in packages:
        install_package(pkg)

def uninstall_fun(packages):

    print(packages)

def list_fun(packages):

    pkg_list = "pkg_list.json"

    with open(pkg_list, "r") as infile:
        content = infile.read()
        obj = json.loads(content)

        for k, v in obj["packages"].items():

            print(k + " (" + v+")")

def read_pkginfo():

    pkginfo = "pkginfo.exa"

    if os.path.isfile(pkginfo):
        
        with open(pkginfo, "r") as infile:
            content = infile.read()
            return json.loads(content)
    
    return None

def write_pkginfo(info_obj):

    json_object = json.dumps(info_obj, indent=4)
 
    with open("pkginfo.exa", "w") as outfile:
        outfile.write(json_object)
    

def create_fun(packages):
    
    print("Creation of package ")

    dict = read_pkginfo()

    if not dict:
        dict = {}

    if "pkg" not in dict:
        dict["pkg"] = {}

    name = input("Package name: "+ ( ("("+dict["pkg"]["name"]+") ") if "name" in dict["pkg"] else ""))

    if name != "":
        dict["pkg"]["name"] = name

    version = input("Version: "+ ( ("("+dict["pkg"]["version"]+") ") if "version" in dict["pkg"] else ""))

    if version != "":
        dict["pkg"]["version"] = version

    desc = input("Description: "+ ( ("("+dict["pkg"]["desc"]+") ") if "desc" in dict["pkg"] else ""))

    if desc != "":
        dict["pkg"]["desc"] = desc

    startcmd = input("Start command: "+ ( ("("+dict["pkg"]["startcmd"]+") ") if "startcmd" in dict["pkg"] else ""))
    
    if startcmd != "":
        dict["pkg"]["startcmd"] = startcmd

    library = input("Is it a library ? (Yes|No) "+ ( ("("+["No","Yes"][dict["pkg"]["library"]]+") ") if "library" in dict["pkg"] else ""))

    if library != "":
        dict["pkg"]["library"] = 1 if (library.lower() == "yes") else 0
    
    write_pkginfo(dict);

    tar = tarfile.open(dict["pkg"]["name"]+".tar", "w")
    tar.add(".")
    tar.close()

    print("\n"+dict["pkg"]["name"]+" package has been created. You can publish it right now or in exaequoOS using exapkg command line tool")
    
    pub = input("Do you want to publish the package now ? (yes|no)")

    if pub.lower() == "yes":

        cred = {}
        
        cred["username"] = input("Username: ")
        cred["password"] = getpass()

        with open(dict["pkg"]["name"]+".tar", "rb") as infile:
            
            content = infile.read()
            res = requests.post('https://exaequOS.com/publish_pkg.php?cred='+base64.b64encode(str(cred).replace("'", '"').encode('ascii')).decode('ascii'), data=content)
            
            if res.status_code == 200:
                print("\nPackage successfully published\n")
            else:
                print("\nA problem occured while publishing the package\n")

def delete_fun(packages):
    
    cred = {}
        
    cred["username"] = input("Username: ")
    cred["password"] = getpass()
    
    res = requests.get('https://exaequOS.com/delete_pkg.php?cred='+base64.b64encode(str(cred).replace("'", '"').encode('ascii')).decode('ascii')+'&pkg='+packages[0])

    print(res.status_code)
    print(res.text)

    if res.status_code == 200:
        print("\nPackage successfully deleted\n")
    else:
        print("\nA problem occured while deleting the package\n")
        
def cmdDescriptions():
   return """
Commands are: 
   search         - search a package
   install        - install a package
   uninstall      - uninstall a package
   list           - list installed packages
   create         - create a package
   delete         - delete a package
"""

def getCmds():
   return ["search", "install", "uninstall", "list", "create", "delete"]
 
def main():
 
    parser = argparse.ArgumentParser(prog='epm', description= 'epm - exaequOS package manager', formatter_class=argparse.RawTextHelpFormatter, epilog=cmdDescriptions())
    
    parser.add_argument('command', choices=getCmds(), help='See commands below')
    parser.add_argument('package', metavar='<package_name>', nargs='*',
                    help='name of the package')
        
    args = parser.parse_args()

    cmds = { "search": search_fun, "install": install_fun, "uninstall": uninstall_fun, "list": list_fun, "create": create_fun, "delete": delete_fun}

    if args.command in ["search", "uninstall", "delete"] and len(args.package) == 0:
        parser.error("Package name is missing");

    cmds[args.command](args.package)
   
if __name__ == "__main__":
    main()
