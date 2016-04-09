#!/usr/bin/env python3
import base64
import logging
import os.path
import subprocess
import sys

devnull = open("/dev/null", "wb")

LDAP_TEMPLATE = ["-Y", "EXTERNAL",
                 "-H", "ldapi://"]
ROOT_DN = "gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth"


CERTCONFIG_TEMPLATE = """\
dn: cn=config
changetype: modify
{mode}: olcTLSCertificateFile
olcTLSCertificateFile: {cert}
-
{mode}: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: {key}"""


def dictify_ldif_content(ldif):
    d = {}
    prevkey = None
    for line in ldif.split("\n"):
        stripped_line = line.strip()
        if not stripped_line:
            continue
        try:
            key, value = stripped_line.split(":", 1)
        except ValueError:
            if line[0].isspace() and prevkey is not None:
                d[prevkey][-1] += line[1:]
                continue
            else:
                raise
        else:
            key = key.casefold().strip()
            value = value.strip()
            if value.startswith("{"):
                number, _, tmpvalue = value.partition("}")
                try:
                    int(number[1:])
                except ValueError:
                    pass
                else:
                    value = tmpvalue
        d.setdefault(key, []).append(value)
        prevkey = key

    for values in d.values():
        for i, value in enumerate(values):
            if value.startswith(":"):
                values[i] = base64.b64decode(
                    value[1:].replace(" ", "").replace("\n", "").encode("ascii")
                ).decode()
    return d


def ldapcall(cmd, args, **kwargs):
    call = LDAP_TEMPLATE.copy()
    call.insert(0, cmd)
    call.extend(args)
    logging.debug("call: %r", call)
    kwargs["stderr"] = subprocess.PIPE
    kwargs["stdout"] = subprocess.PIPE
    input = kwargs.pop("input", None)
    if input:
        kwargs["stdin"] = subprocess.PIPE
    proc = subprocess.Popen(
        call, **kwargs
    )
    stdout, stderr = proc.communicate(input)
    returncode = proc.wait()
    if returncode != 0:
        logging.error("called process failed: %r\n%s",
                      call,
                      stderr.decode())
        if input:
            logging.info("input was: \n%s",
                         input.decode())
        raise subprocess.CalledProcessError(returncode, call)
    result = stdout.decode()
    logging.debug("result: %s", result)
    return result


def util_find_database_dn(database_suffix):
    args = [
        "-LLL",
        "-b", "cn=config",
        "olcSuffix={}".format(database_suffix),
        "dn"
    ]
    data = dictify_ldif_content(ldapcall("ldapsearch", args))
    if not data:
        raise LookupError("No such database")
    return data["dn"][0]


def modify(ldif):
    args = []
    return ldapcall("ldapmodify", args, input=ldif)


def add(ldif):
    args = []
    return ldapcall("ldapadd", args, input=ldif)


def escape_value(value):
    try:
        value.encode("ascii")
        return " "+value
    except UnicodeEncodeError:
        return ": "+base64.b64encode(value.encode("utf8")).decode("ascii")


class LDAPInterface:
    def __init__(self):
        self._changed = False
        self._searchcache = {}

    def _flag_changed(self):
        self._changed = True
        self._searchcache = {}

    def _query_cache(self, tag):
        return self._searchcache[tag]

    def _cache(self, tag, value):
        self._searchcache[tag] = value

    @property
    def changed(self):
        return self._changed

    def add_new(self, dn, objectclasses, *attrs):
        attrs = ([("dn", dn),] +
                 [("objectClass", cls) for cls in objectclasses] +
                 list(attrs))
        ldif = "\n".join(
            "{}:{}".format(
                key, escape_value(value)
            ) for key, value in attrs)
        return add(ldif.encode("ascii"))

    def search(self, dn):
        tag = (dn, )
        try:
            value = self._query_cache(tag)
        except KeyError:
            logging.debug("cache miss for %r", tag)
        else:
            logging.debug("cache hit for %r", tag)
            return value

        args = ["-LLL"]
        args.extend(["-s", "base"])
        args.extend(["-b", dn])
        args.extend(["*", "+"])

        result = dictify_ldif_content(ldapcall("ldapsearch", args))
        self._cache(tag, result)
        return result

    def delattr(self, dn, attrname, value=None):
        ldif = """\
dn: {dn}
changetype: modify
delete: {attrname}""".format(dn=dn,
            attrname=attrname).encode("ascii")
        if value is not None:
            ldif += b"\n{}:{}".format(attrname, value)
        ldif += b"\n-"
        return modify(ldif)

    def setattr(self, dn, attrname, *values, using="replace"):
        values = list(map(escape_value, values))
        ldif = """\
dn: {dn}
changetype: modify
{using}: {attrname}
""".format(dn=dn,
            attrname=attrname,
            using=using)
        ldif += "\n".join(
            "{}:{!s}".format(attrname, value)
            for value in values)
        ldif += "\n-"
        return modify(ldif.encode("ascii"))

    def ensure_attr_has_value(
            self, dn, attrname, value,
            *,
            replace=True):
        logging.info("ensuring that attr %r of %s is %r",
                     attrname, dn, value)

        data = self.search(dn)
        values = data.get(attrname.casefold(), [])
        if value in values:
            logging.info("value already in place")
            return None

        if not values or not replace:
            using = "add"
        else:
            using = "replace"

        logging.info("setting value (using = %r)", using)
        result = self.setattr(dn, attrname, value, using=using)
        self._flag_changed()
        return result

    def ensure_attr_values(
            self, dn, attrname, values):
        data = self.search(dn)
        logging.info("ensuring that values of attr %r of %s are %r",
                     attrname, dn, values)
        actual_values = data.get(attrname.casefold(), [])
        if values == actual_values:
            return None

        print(values)
        print(actual_values)

        self._flag_changed()

        using = "replace" if actual_values else "add"

        self.setattr(dn, attrname, *values, using=using)

    def find_real_dn(self, base, dn):
        if not dn.endswith(base):
            raise ValueError("find_real_dn requires that dn ends with base")

        part_dn = dn[:-(len(base)+1)]
        args = [
            "-LLL",
            "-b", base,
            part_dn
        ]

        return dictify_ldif_content(ldapcall("ldapsearch", args))["dn"][0]

    def ensure_object(self, dn, objectclasses, *attrs, strict=True,
                      fuzzy_base=None):
        if isinstance(objectclasses, str):
            objectclasses = set([objectclasses])
        else:
            objectclasses = set(objectclasses)

        logging.info("ensuring presence of %s", dn)

        if fuzzy_base:
            try:
                dn = self.find_real_dn(fuzzy_base, dn)
            except KeyError:
                pass

        try:
            data = self.search(dn)
        except (subprocess.CalledProcessError, KeyError):
            data = {}
        if not data:
            logging.info("failed to retrieve object, creating ...")
            self.add_new(dn, objectclasses, *attrs)
            self._flag_changed()
            return

        if set(data["objectclass"]) != objectclasses:
            raise ValueError("Existing object has incorrect classes: {}".format(
                objectclasses))

        if not strict:
            return

        logging.info("ensuring that all attributes of %s match", dn)
        attr_dict = {}
        for key, value in attrs:
            attr_dict.setdefault(key, []).append(value)

        for key, values in attr_dict.items():
            self.ensure_attr_values(dn, key, values)

        return

    def ensure_schema(self, cn, schema_dir):
        logging.info("ensuring schema cn=%s", cn)
        args = [
            "-LLL",
            "-b", "cn=schema,cn=config",
            "(cn={{*}}{})".format(cn),
            "dn"
        ]
        data = dictify_ldif_content(ldapcall("ldapsearch", args))
        if data:
            dn = data["dn"][0]
            logging.info("schema is present, with dn: %s", dn)
            return dn

        filename = os.path.join(schema_dir, "{}.ldif".format(cn))
        logging.info("loading schema from %r", filename)
        args = [
            "-f", filename
        ]
        ldapcall("ldapadd", args)

    def load_module(self, module_name):
        args = [
            "-LLL",
            "-b", "cn=config",
            "(&(cn=module*)(!(olcModulePath=*)))",
            "dn"
        ]
        data = dictify_ldif_content(ldapcall("ldapsearch", args))
        if data:
            dn = data["dn"][0]
            self.ensure_attr_has_value(
                dn,
                "olcModuleLoad", module_name,
                replace=False
            )
        else:
            self.add_new(
                "cn=module,cn=config",
                ["olcModuleList"],
                ("olcModuleLoad", module_name)
            )
            self._flag_changed()

    def make_database(self, suffix, root_dn, database_dir):
        self.add_new(
            "olcDatabase=mdb,cn=config",
            ["olcDatabaseConfig", "olcMdbConfig"],
            ("olcDatabase", "mdb"),
            ("olcDbDirectory", database_dir),
            ("olcRootDN", root_dn),
            ("olcSuffix", suffix)
        )
        self._flag_changed()


def ensure_group(ldap, domain, groupname, gidnumber, description=None):
    additional_attrs = []
    if description:
        additional_attrs.append(
            ("description", description)
        )
    ldap.ensure_object(
        "cn={},ou=Group,".format(groupname)+domain,
        ["posixGroup"],
        ("gidNumber", str(gidnumber)),
        *additional_attrs
    )


def configure_ldap_domain_common(args, ldap, database_dn):
    # 1 GiB ought to be enough
    ldap.ensure_attr_has_value(
        database_dn, "olcDbMaxSize", str(2**30))
    ldap.ensure_attr_has_value(
        database_dn, "olcRootDN", ROOT_DN)
    ldap.ensure_attr_values(
        database_dn, "olcAccess",
        [
            "to *\
 by dn.base=cn=replicator,ou=Management,{domain} read\
 by * break".format(domain=args.domain),
            "to attrs=authzTo\
 by * read",
            "to attrs=userPassword\
 by dn=cn=AuthManager,ou=Management,{domain} manage\
 by self write\
 by anonymous auth\
 by * none".format(domain=args.domain),
            "to attrs=mailLocalAddress,uidNumber,gidNumber,objectClass,homeDirectory\
 by dn=cn=AuthManager,ou=Management,{domain} manage\
 by * read".format(domain=args.domain),
            "to dn.subtree=ou=Account,{domain}\
 by dn=cn=AuthManager,ou=Management,{domain} write\
 by self write\
 by * read".format(domain=args.domain),
            "to dn.subtree=ou=Group,{domain}\
 by dn=cn=AuthManager,ou=Management,{domain} write\
 by * read".format(domain=args.domain),
            "to *\
 by self write\
 by * read"""
        ])
    ldap.ensure_attr_values(
        database_dn, "olcDbIndex",
        [
            "objectClass pres,eq",
            "uid pres,sub,eq",
            "uidNumber eq",
            "gidNumber eq",
            "member pres,eq",
            "memberUid pres,eq",
            "mailLocalAddress pres,eq",
            "entryCSN eq",
            "entryUUID eq",
            "cn eq",
        ]
    )


def configure_ldap_domain(args, ldap):
    try:
        database_dn = util_find_database_dn(args.domain)
    except LookupError:
        logging.warning("no such database, trying to create database")
        ldap.make_database(database_dir=args.database_dir,
                           suffix=args.domain,
                           root_dn=ROOT_DN)
        database_dn = util_find_database_dn(args.domain)

    ldap.ensure_attr_has_value(
        database_dn, "olcSuffix", args.domain)

    configure_ldap_domain_common(args, ldap, database_dn)

    ldap.ensure_object(
        args.domain, ["dcObject", "top", "organization"],
        ("o", args.fqdn),
        ("description", args.description)
    )

    ldap.ensure_object(
        "ou=Management,"+args.domain, "organizationalUnit",
        ("ou", "Management"),
        ("description", "Unit to group DNs which are used by tools to log in"
                        " with additional privilegues")
    )

    ldap.ensure_object(
        "ou=Account,"+args.domain, "organizationalUnit",
        ("ou", "Account"),
        ("description", "POSIX account DNs")
    )

    ldap.ensure_object(
        "ou=Group,"+args.domain, "organizationalUnit",
        ("ou", "Group"),
        ("description", "POSIX group DNs")
    )

    ldap.ensure_object(
        "ou=Permission,"+args.domain, "organizationalUnit",
        ("ou", "Permission"),
        ("description", "Permission lists")
    )

    ldap.ensure_object(
        "cn=admin,ou=Permission,"+args.domain, "groupOfNames",
        ("cn", "admin"),
        ("member", "cn=dummy")
    )

    ldap.ensure_object(
        "ou=IDPool,"+args.domain,
        [
            "organizationalUnit",
        ],
        ("ou", "IDPool"),
    )

    ldap.ensure_object(
        "ou=uids,ou=IDPool,"+args.domain,
        [
            "organizationalUnit",
            "uidPool",
        ],
        ("ou", "uids"),
        ("cn", "LDAP user UID Pool"),
        ("uidNumber", "10000"),
        strict=False
    )

    ldap.ensure_object(
        "ou=gids,ou=IDPool,"+args.domain,
        [
            "organizationalUnit",
            "gidPool",
        ],
        ("ou", "uids"),
        ("cn", "LDAP user GID Pool"),
        ("gidNumber", "10000"),
        strict=False
    )

    ldap.ensure_object(
        "cn=AuthManager,ou=Management,"+args.domain, "person",
        ("sn", "Authentication Manager"),
        ("userpassword", args.admin_dn_password))

    ldap.ensure_object(
        "cn=RemoteManager,ou=Management,"+args.domain, "person",
        ("sn", "Remote Manager"),
        ("userpassword", args.admin_dn_password),
        ("authzTo", "dn:cn=AuthManager,ou=Management,"+args.domain),
    )

    if args.replicator_dn_password:
        ldap.load_module("syncprov.la")

        ldap.ensure_object(
            "olcOverlay=syncprov,"+database_dn,
            ["olcOverlayConfig", "olcSyncProvConfig"],
            fuzzy_base=database_dn
        )

        ldap.ensure_object(
            "cn=replicator,ou=Management,"+args.domain, "person",
            ("sn", "Replication user"),
            ("userpassword", args.replicator_dn_password))

    ensure_group(
        ldap, args.domain, "sftponly", 1099,
        "Users in this group only gain SFTP instead of full shell access on "
        "some hosts."
    )
    ensure_group(
        ldap, args.domain, "ldapuser", 1098,
        "Removing users from this group will give them more permissions "
        "than intended.")


def configure_ldap_server(args, ldap):
    ldap.load_module("back_ldap.la")
    ldap.load_module("back_mdb.la")
    ldap.load_module("back_hdb.la")

    ldap.ensure_schema("core", schema_dir=args.schema_dir)
    ldap.ensure_schema("corba", schema_dir=args.schema_dir)
    ldap.ensure_schema("cosine", schema_dir=args.schema_dir)
    ldap.ensure_schema("nis", schema_dir=args.schema_dir)
    ldap.ensure_schema("inetorgperson", schema_dir=args.schema_dir)
    ldap.ensure_schema("misc", schema_dir=args.schema_dir)
    ldap.ensure_schema("idpool", schema_dir=args.schema_dir)
    ldap.ensure_schema("hijack1", schema_dir=args.schema_dir)
    ldap.ensure_schema("hijack2", schema_dir=args.schema_dir)
    ldap.ensure_schema("hijack3", schema_dir=args.schema_dir)

    if args.debug:
        ldap.ensure_attr_values(
            "cn=config",
            "olcLogLevel",
            [
                "-1",
            ]
        )
    else:
        ldap.ensure_attr_values(
            "cn=config",
            "olcLogLevel",
            [
                "none",
            ]
        )

    if args.tls:
        try:
            modify(CERTCONFIG_TEMPLATE.format(
                key="/etc/ldap/privkey.pem",
                cert="/etc/ldap/cert.pem",
                mode="add").encode("ascii"))
        except subprocess.CalledProcessError:
            modify(CERTCONFIG_TEMPLATE.format(
                key="/etc/ldap/privkey.pem",
                cert="/etc/ldap/cert.pem",
                mode="replace").encode("ascii"))

        ldap.ensure_attr_has_value(
            "cn=config",
            "olcTLSCACertificateFile",
            "/etc/ldap/cacert.pem",
            replace=True
        )

    ldap.ensure_attr_values(
        "cn=config",
        "olcAuthzPolicy",
        [
            "to"
        ]
    )


def configure_ldap_syncrepl_slave(args, ldap):
    ldap.load_module("syncprov.la")
    ldap.load_module("back_monitor.la")

    database_dn = util_find_database_dn(args.base)

    callargs = [
        "-LLL",
        "-b", "cn=config",
        "(&(olcDatabase=ldap)(olcSuffix={}))".format(
            args.base,
            args.peer),
        "dn", "olcDbURI",
    ]

    try:
        data = dictify_ldif_content(
            ldapcall("ldapsearch", callargs)
        )

        for dn, uri in zip(data["dn"], data["olcdburi"]):
            if uri == "ldap://"+args.peer:
                break
        else:
            raise KeyError(args.peer)
    except (subprocess.CalledProcessError, KeyError):
        logging.debug("ldap proxy db does not exist yet")
        ldap.add_new(
            "olcDatabase=ldap,cn=config",
            [
                "olcDatabaseConfig",
                "olcLdapConfig"
            ],
            ("olcDatabase", "ldap"),
            ("olcHidden", "TRUE"),
            ("olcSuffix", args.base),
            ("olcRootDN", "cn=slapd-ldap"),
            ("olcDbURI", "ldap://{}".format(args.peer)),
            ("olcLastMod", "TRUE"),
            ("olcRestrict", "all"),
            (
                "olcSyncrepl",
                'rid={rid} '
                'provider=ldap://localhost '
                'binddn="cn=replicator,ou=Management,{base}" '
                'bindmethod=simple '
                'credentials=XXXx{passwd} '
                'searchbase="{base}" '
                'type=refreshAndPersist '
                'retry="5 5 300 5" '
                ''.format(
                    base=args.base,
                    passwd=args.auth_pass,
                    rid=args.rid
                )
            ),
            (
                "olcDbACLBind",
                'bindmethod=simple '
                'binddn="cn=replicator,ou=Management,{}" '
                'credentials=XXXx{}'.format(
                    args.base,
                    args.auth_pass
                )
            )
        )
        ldap._flag_changed()

        data = dictify_ldif_content(
            ldapcall("ldapsearch", callargs)
        )

        for dn, uri in zip(data["dn"], data["olcdburi"]):
            if uri == "ldap://"+args.peer:
                break
        else:
            raise KeyError(args.peer)

    ldap.ensure_object(
        "olcOverlay=syncprov,"+dn,
        ["olcOverlayConfig", "olcSyncProvConfig"],
        fuzzy_base=dn
    )


def configure_ldap_slave_domain(args, ldap):
    try:
        database_dn = util_find_database_dn(args.domain)
    except LookupError:
        logging.warning("no such database, trying to create database")
        ldap.make_database(database_dir=args.database_dir,
                           suffix=args.domain,
                           root_dn=ROOT_DN)
        database_dn = util_find_database_dn(args.domain)

    ldap.ensure_attr_has_value(
        database_dn, "olcSuffix", args.domain)

    configure_ldap_domain_common(args, ldap, database_dn)

    ldap.ensure_attr_has_value(
        database_dn,
        "olcSyncRepl",
        'rid=001 '
        'provider=ldap://{master} '
        'searchbase="{base}" '
        'type=refreshAndPersist '
        'retry="5 +" '
        'bindmethod=simple '
        'binddn="cn=replicator,ou=Management,{base}" '
        'credentials="{passwd}" '
        ''.format(
            master=args.master,
            base=args.domain,
            passwd=args.replicator_dn_password
        )
    )

    ldap.ensure_attr_values(
        database_dn,
        "olcUpdateRef",
        ["ldap://{}".format(args.master)],
    )

    ldap.ensure_object(
        "olcOverlay={0}chain,olcDatabase={-1}frontend,cn=config",
        ["olcOverlayConfig", "olcChainConfig"],
        ("olcOverlay", "{0}chain"),
        ("olcChainReturnError", "TRUE"),
        strict=False,
    )

    ldap.ensure_object(
        "olcDatabase={0}ldap,olcOverlay={0}chain,olcDatabase={-1}frontend,cn=config",
        ["olcLDAPConfig", "olcChainDatabase"],
        ("olcDBURI", "ldap://{}".format(args.master)),
        ("olcDbIDAssertBind", """bindmethod=simple binddn="cn=RemoteManager,ou=Management,dc=zombofant,dc=net" credentials="{pwd}" mode=self""".format(pwd=args.admin_dn_password)),
        ("olcDbRebindAsUser", "TRUE"),
    )


if __name__ == "__main__":
    import argparse

    main_parser = argparse.ArgumentParser()

    subparsers = main_parser.add_subparsers()

    parser = subparsers.add_parser("master-domain")
    parser.set_defaults(func=configure_ldap_domain)
    parser.add_argument("--description", default="No description")
    parser.add_argument("--database-dir", default=None)
    parser.add_argument("--database-type", default="mdb")
    parser.add_argument("--replicator-dn-password", default=None)
    parser.add_argument("domain")
    parser.add_argument("fqdn")
    parser.add_argument("admin_dn_password")

    parser = subparsers.add_parser("slave-domain")
    parser.set_defaults(func=configure_ldap_slave_domain)
    parser.add_argument("--database-dir", default=None)
    parser.add_argument("--database-type", default="mdb")
    parser.add_argument("domain")
    parser.add_argument("fqdn")
    parser.add_argument("replicator_dn_password")
    parser.add_argument("master")
    parser.add_argument("admin_dn_password")

    parser = subparsers.add_parser("server")
    parser.set_defaults(func=configure_ldap_server)
    parser.add_argument("--schema-dir", default="/etc/openldap/schema/")
    parser.add_argument(
        "--debug",
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "--no-debug",
        action="store_false",
        dest="debug"
    )

    parser.add_argument(
        "--tls",
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "--no-tls",
        action="store_false",
        dest="tls"
    )

    parser = subparsers.add_parser("syncrepl-slave")
    parser.set_defaults(func=configure_ldap_syncrepl_slave)
    parser.add_argument("peer")
    parser.add_argument("base")
    parser.add_argument("auth_pass")
    parser.add_argument("rid")

    args = main_parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG,
        format="{}:%(levelname)-8s %(message)s".format(
            os.path.basename(sys.argv[0]))
    )

    ldap = LDAPInterface()

    args.func(args, ldap)

    if ldap.changed:
        sys.exit(10)
    sys.exit(0)
