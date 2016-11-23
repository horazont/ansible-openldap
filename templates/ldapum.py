#!/usr/bin/python3
import base64
import crypt
import getpass
import hashlib
import random
import subprocess
import types

SALT_BYTES = 16

rng = random.SystemRandom()

USER_TEMPLATE = """\
dn: uid={uid},ou=Account,{base}
objectClass: inetOrgPerson
objectClass: inetLocalMailRecipient
uid: {uid}
cn: {cn}
sn: {sn}
givenName: {given_name}
mail: {mail}
userPassword:: {password_base64}\n"""

GROUP_TEMPLATE = """\
dn: cn={name},ou=Group,{base}
objectClass: posixGroup
gidNumber: {gid}
\n"""

PASSWD_TEMPLATE = """\
dn: uid={uid},ou=Account,{base}
changetype: modify
replace: userPassword
userPassword:: {password_base64}
-\n"""

USERDEL_TEMPLATE = """\
dn: uid={uid},ou=Account,{base}
changetype: delete\n"""

ADD_MAIL_ALIAS_TEMPLATE = """\
add: mailLocalAddress
mailLocalAddress: {addr}
-\n"""

REMOVE_MAIL_ALIAS_TEMPLATE = """\
delete: mailLocalAddress
mailLocalAddress: {addr}
-\n"""

ENABLE_LOGIN_TEMPLATE = """\
dn: uid={uid},ou=Account,{base}
changetype: modify
add: objectclass
objectclass: posixAccount
-
add: uidNumber
uidNumber: {uid_number}
-
add: gidNumber
gidNumber: {gid_number}
-
add: homeDirectory
homeDirectory: {home}
-
add: loginShell
loginShell: /bin/bash
-\n"""

ADD_TO_GROUP_TEMPLATE = """\
dn: cn={group},ou=Group,{base}
changetype: modify
add: memberUid
memberUid: {uid}
-\n"""

REMOVE_FROM_GROUP_TEMPLATE = """\
dn: cn={group},ou=Group,{base}
changetype: modify
delete: memberUid
memberUid: {uid}
-\n"""

UPGRADE_TEMPLATE = """\
dn: uid={uid},ou=Account,{base}
changetype: modify
add: objectClass
objectClass: inetLocalMailRecipient
-\n"""

RENAME_USER_WITHOUT_SHELL_TEMPLATE = """\
dn: uid={uid},ou=Account,{base}
changetype: modrdn
newrdn: uid={newuid}
deleteoldrdn: 0

dn: uid={newuid},ou=Account,{base}
changetype: modify
replace: uid
uid: {newuid}
-\n"""


def ask_pass():
    pwd1 = getpass.getpass().encode("utf-8")
    if not pwd1:
        raise ValueError("password must not be empty")
    return pwd1


def ask_pass_new():
    pwd1 = getpass.getpass().encode("utf-8")
    pwd2 = getpass.getpass('Confirm: ').encode("utf-8")
    if pwd1 != pwd2:
        raise ValueError("passwords do not match")
    if not pwd1:
        raise ValueError("password must not be empty")
    return pwd1


def ask_pass_or_exit(asker=ask_pass):
    try:
        return asker()
    except ValueError as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)


def crypt_password(password):
    return "{crypt}"+crypt.crypt(password)


def useradd(args):
    if args.password is None:
        args.password = ask_pass_or_exit(ask_pass_new)

    instance = USER_TEMPLATE.format(
        uid=args.uid,
        cn=args.cn,
        sn=args.sn,
        given_name=args.given_name,
        mail=args.mail,
        base=args.base,
        password_base64=base64.b64encode(crypt_password(args.password)))

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapadd",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


def groupadd(args):
    instance = GROUP_TEMPLATE.format(
        gid=args.gid,
        name=args.name,
        base=args.base
    )

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapadd",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


def passwd(args):
    if args.crypted_password is not None:
        password_crypted = "{crypt}"+args.crypted_password
    else:
        if args.password is None:
            args.password = ask_pass_or_exit(ask_pass_new)
        password_crypted = crypt_password(args.password)

    instance = PASSWD_TEMPLATE.format(
        uid=args.uid,
        base=args.base,
        password_base64=base64.b64encode(
            password_crypted.encode("ascii")
        ).decode("ascii")
    )

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapmodify",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


def mailaddress_add(args):
    instance = "dn: uid={},ou=Account,{}\nchangetype: modify\n".format(
        args.uid,
        args.base
    )
    instance += "".join(
        ADD_MAIL_ALIAS_TEMPLATE.format(addr=addr)
        for addr in args.addrs
    )

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapmodify",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


def upgrade(args):
    instance = UPGRADE_TEMPLATE.format(
        uid=args.uid,
        base=args.base,
    )

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapmodify",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


def mailaddress_remove(args):
    instance = "dn: uid={},ou=Account,{}\nchangetype: modify\n".format(args.uid, args.base)
    instance += "".join(
        REMOVE_MAIL_ALIAS_TEMPLATE.format(addr=addr)
        for addr in args.addrs
    )

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapmodify",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


def mailaddress_list(args):
    try:
        print(subprocess.check_output(
            [
                "ldapsearch",
                "-Y", "EXTERNAL",
                "-H", "ldapi://",
                "-LLL",
                "-b", "ou=Account,dc=zombofant,dc=net",
                "uid={}".format(args.uid),
                "mailLocalAddress",
            ]
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


def enable_login(args):
    instance = ENABLE_LOGIN_TEMPLATE.format(
        uid=args.uid,
        base=args.base,
        uid_number=args.uid_number,
        gid_number=args.gid_number,
        home=args.home or "/home/{}".format(args.uid)
    )

    ns = types.SimpleNamespace()
    ns.base = args.base
    ns.uid = args.uid
    ns.group = "ldapuser"
    ns.dry_run = args.dry_run

    if args.dry_run:
        print(instance)
        user_add_to_group(ns)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapmodify",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)
    user_add_to_group(ns)


def userdel(args):
    instance = USERDEL_TEMPLATE.format(
        uid=args.uid,
        base=args.base,
    )

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapmodify",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


def user_add_to_group(args):
    instance = ADD_TO_GROUP_TEMPLATE.format(
        uid=args.uid,
        group=args.group,
        base=args.base,
    )

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapmodify",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


def user_remove_from_group(args):
    instance = REMOVE_FROM_GROUP_TEMPLATE.format(
        uid=args.uid,
        group=args.group,
        base=args.base,
    )

    if args.dry_run:
        print(instance)
        return

    try:
        print(subprocess.check_output(
            [
                "ldapmodify",
                "-Y", "EXTERNAL",
                "-H", "ldapi://"
            ],
            input=instance.encode()
        ).decode())
    except subprocess.CalledProcessError:
        print("failed")
        sys.exit(1)


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d", "--dry-run",
        default=False,
        action="store_true",
        help="Do not make any changes, but dump possible ldif output to stdout"
    )

    parser.add_argument(
        "base",
        help="Base DN to use"
    )

    subparsers = parser.add_subparsers(
        help="Function to invoke",
    )

    sparser = subparsers.add_parser("userdel")
    sparser.set_defaults(func=userdel)
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="Alphanumeric user identifier of the user to delete"
    )

    sparser = subparsers.add_parser("useradd")
    sparser.set_defaults(func=useradd)
    sparser.add_argument(
        "--password",
        default=None,
        metavar="PASSWORD",
        help="Initial password. If omitted, prompt for password on stdin."
    )
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="Alphanumeric user identifier. Must be unique, cannot be changed"
    )
    sparser.add_argument(
        "cn",
        metavar="DISPLAYNAME",
        help="Ideally full name, displayed possibly everywhere"
    )
    sparser.add_argument(
        "--sn",
        metavar="SURNAME",
        default="XXX",
        help="Family name"
    )
    sparser.add_argument(
        "--given-name",
        metavar="GIVENNAME",
        default="XXX",
        help="Given name"
    )
    sparser.add_argument(
        "mail",
        metavar="MAIL",
        help="E-Mail address under which the user can be reached"
    )

    sparser = subparsers.add_parser("groupadd")
    sparser.set_defaults(func=groupadd)
    sparser.add_argument(
        "name",
        metavar="USERNAME",
        help="Alphanumeric group identifier. Must be unique, cannot be changed"
    )
    sparser.add_argument(
        "gid",
        metavar="NUMBER",
        type=int,
        help="Numeric group identifier. Must be unique, cannot be changed"
    )

    sparser = subparsers.add_parser("passwd")
    sparser.set_defaults(func=passwd)

    group = sparser.add_mutually_exclusive_group()
    group.add_argument(
        "--password",
        default=None,
        metavar="PASSWORD",
        help="New password. If omitted, prompt for password on stdin."
    )
    group.add_argument(
        "--crypted-password",
        metavar="CRYPT",
        default=None,
        help="New password as crypt() hash",
    )


    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="Alphanumeric user identifier of the user whose password shall be"
        " changed"
    )

    sparser = subparsers.add_parser("mailaddress-add")
    sparser.set_defaults(func=mailaddress_add)
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="UID of the user to modify"
    )
    sparser.add_argument(
        "addrs",
        nargs="+",
        metavar="MAILADDRESS",
        help="Mail aliases to add, must be full mail addresses"
    )

    sparser = subparsers.add_parser("upgrade")
    sparser.set_defaults(func=upgrade)
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="UID of the user to modify"
    )

    sparser = subparsers.add_parser("user-add-to-group")
    sparser.set_defaults(func=user_add_to_group)
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="UID of the user to add to a group"
    )
    sparser.add_argument(
        "group",
        metavar="GROUP",
        help="Name of the group"
    )

    sparser = subparsers.add_parser("user-remove-from-group")
    sparser.set_defaults(func=user_remove_from_group)
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="UID of the user to remove from a group"
    )
    sparser.add_argument(
        "group",
        metavar="GROUP",
        help="Name of the group"
    )

    sparser = subparsers.add_parser("mailaddress-remove")
    sparser.set_defaults(func=mailaddress_remove)
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="UID of the user to modify"
    )
    sparser.add_argument(
        "addrs",
        nargs="+",
        metavar="MAILADDRESS",
        help="Mail aliases to add, must be full mail addresses"
    )

    sparser = subparsers.add_parser("mailaddress-list")
    sparser.set_defaults(func=mailaddress_list)
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="UID of the user whose addresses to list"
    )

    sparser = subparsers.add_parser("login-enable")
    sparser.set_defaults(func=enable_login)
    sparser.add_argument(
        "-d", "--home-directory",
        dest="home",
        default=None,
        help="Home directory, defaults to /home/{uid}"
    )
    sparser.add_argument(
        "uid",
        metavar="USERNAME",
        help="UID of the user to modify"
    )
    sparser.add_argument(
        "uid_number",
        type=int,
        help="Numeric UID to assign to the user",
        metavar="NUMBER"
    )
    sparser.add_argument(
        "gid_number",
        type=int,
        help="Numeric GID to assign to the user",
        metavar="NUMBER"
    )

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        print("no function selected")
        sys.exit(1)

    args.func(args)
