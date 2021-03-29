#!/usr/bin/env python3
'''
Generate a top-level makefile that builds the Osmocom 2G + 3G network components.

  ./gen_makefile.py projects.deps [configure.opts [more.opts]] [-o Makefile.output]

Configured by text files:

  *.deps: whitespace-separated listing of
    project_name depends_on_project_1 depends_on_project_2 ...

  *.opts: whitespace-separated listing of
    project_name --config-opt-1 --config-opt-2 ...

Thus it is possible to choose between e.g.
- 2G+3G or 2G-only by picking a different projects_and_deps.conf,
- and between building each of those with or without mgcp transcoding support
  by picking a different configure_opts.conf.

From the Makefile nature, the dependencies extend, no need to repeat common deps.

When this script is done, a Makefile has been generated that allows you to
build all projects at once by issuing 'make', but also to refresh only parts of
it when some bits in the middle have changed. The makefile keeps local progress
marker files like .make.libosmocore.configure; if such progress marker is
removed or becomes outdated, that step and all dependent ones are re-run.
This is helpful in daily hacking across several repositories.

Note that by default, this includes 'sudo ldconfig' calls following each
installation. You may want to permit your user to run 'sudo ldconfig' without
needing a password, e.g. by

  sudo sh -c "echo '$USER  ALL= NOPASSWD: /sbin/ldconfig' > /etc/sudoers.d/${USER}_ldconfig"

You can skip the 'sudo ldconfig' by issuing the --no-ldconfig option.

You can run 'ldconfig' without sudo by issuing the --ldconfig-without-sudo option.

By default, it is assumed that your user has write permission to /usr/local. If you
need sudo to install there, you may issue the --sudo-make-install option.

EXAMPLE:

  ./gen_makefile.py 3G+2G.deps default.opts iu.opts -I -m build
  cd build
  make

'''

import sys
import os
import argparse

parser = argparse.ArgumentParser(epilog=__doc__, formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('projects_and_deps_file',
  help='''Config file containing projects to build and
dependencies between those''')

parser.add_argument('configure_opts_files',
  help='''Config file containing project name and
./configure options''',
  nargs='*')

parser.add_argument('-m', '--make-dir', dest='make_dir',
  help='''Place Makefile in this dir (default: create
a new dir named after deps and opts files).''')

parser.add_argument('-s', '--src-dir', dest='src_dir', default='./src',
  help='Parent dir for all git clones.')

parser.add_argument('-b', '--build-dir', dest='build_dir',
  help='''Parent dir for all build trees (default:
directly in the make-dir).''')

parser.add_argument('-u', '--url', dest='url', default='git://git.osmocom.org',
  help='''git clone base URL. Default is 'git://git.osmocom.org'.
e.g. with a config like this in your ~/.ssh/config:
  host go
  hostname gerrit.osmocom.org
  port 29418
you may pass '-u ssh://go' to be able to submit to gerrit.''')

parser.add_argument('-p', '--push-url', dest='push_url', default='',
  help='''git push-URL. Default is to not configure a separate push-URL.''')

parser.add_argument('-o', '--output', dest='output', default='Makefile',
  help='''Makefile filename (default: 'Makefile').''')

parser.add_argument('-j', '--jobs', dest='jobs', default='9',
  help='''-j option to pass to 'make'.''')

parser.add_argument('-I', '--sudo-make-install', dest='sudo_make_install',
  action='store_true',
  help='''run 'make install' step with 'sudo'.''')

parser.add_argument('-L', '--no-ldconfig', dest='no_ldconfig',
  action='store_true',
  help='''omit the 'sudo ldconfig' step.''')

parser.add_argument('--ldconfig-without-sudo', dest='ldconfig_without_sudo',
  action='store_true',
  help='''call just 'ldconfig', without sudo, which implies
root privileges (not recommended)''')

parser.add_argument('-c', '--no-make-check', dest='make_check',
  default=True, action='store_false',
  help='''do not 'make check', just 'make' to build.''')

args = parser.parse_args()

class listdict(dict):
  'a dict of lists { "a": [1, 2, 3],  "b": [1, 2] }'

  def add(self, name, item):
    l = self.get(name)
    if not l:
      l = []
      self[name] = l
    l.append(item)

  def extend(self, name, l):
    for v in l:
      self.add(name, v)

  def add_dict(self, d):
    for k,v in d.items():
      self.add(k, v)

  def extend_dict(self, d):
    for k,v in d.items():
      l = self.extend(k, v)

def read_projects_deps(path):
  'Read deps config and return tuples of (project_name, which-other-to-build-first).'
  l = []
  for line in open(path):
    line = line.strip()
    if not line or line.startswith('#'):
      continue
    tokens = line.split()
    l.append((tokens[0], tokens[1:]))
  return l

def read_configure_opts(path):
  'Read config opts file and return tuples of (project_name, config-opts).'
  if not path:
    return {}
  return dict(read_projects_deps(path))

def gen_make(proj, deps, configure_opts, jobs, make_dir, src_dir, build_dir, url, push_url, sudo_make_install, no_ldconfig, ldconfig_without_sudo, make_check):
  branch = 'master'
  if deps is not None and len(deps) > 0:
    branch = deps[0]
    deps = deps[1:]

  src_proj = os.path.join(src_dir, proj)
  if proj == 'openbsc':
    src_proj = os.path.join(src_proj, 'openbsc')
  build_proj = os.path.join(build_dir, proj)

  make_to_src = os.path.relpath(src_dir, make_dir)
  make_to_src_proj = os.path.relpath(src_proj, make_dir)
  make_to_build_proj = os.path.relpath(build_proj, make_dir)
  build_to_src = os.path.relpath(src_proj, build_proj)

  if configure_opts:
    configure_opts_str = ' '.join(configure_opts)
  else:
    configure_opts_str = ''

  return r'''
### {proj} ###

{proj}_configure_files := $(shell find {src_proj} -name "Makefile.am" -or -name "*.in" -and -not -name "Makefile.in" -and -not -name "config.h.in" )
{proj}_files := $(shell find {src_proj} -name "*.[hc]" -or -name "*.py" -or -name "*.cpp" -or -name "*.tpl" -or -name "*.map")

.make.{proj}.clone:
	@echo -e "\n\n\n===== $@\n"
	test -d {src} || mkdir -p {src}
	test -d {src_proj} || ( git -C {src} clone "{url}/{proj}" "{proj}" && git -C "{src}/{proj}" checkout "{branch}" && git -C "{src}/{proj}" remote set-url --push origin "{push_url}/{proj}")
	sync
	touch $@

.make.{proj}.autoconf: .make.{proj}.clone {src_proj}/configure.ac
	@echo -e "\n\n\n===== $@\n"
	-rm -f {src_proj}/.version
	cd {src_proj}; autoreconf -fi
	sync
	touch $@
	
.make.{proj}.configure: .make.{proj}.autoconf {deps_installed} $({proj}_configure_files)
	@echo -e "\n\n\n===== $@\n"
	-chmod -R ug+w {build_proj}
	-rm -rf {build_proj}
	mkdir -p {build_proj}
	cd {build_proj}; {build_to_src}/configure {configure_opts}
	sync
	touch $@

.make.{proj}.build: .make.{proj}.configure $({proj}_files)
	@echo -e "\n\n\n===== $@\n"
	$(MAKE) -C {build_proj} -j {jobs} {check}
	sync
	touch $@

.make.{proj}.install: .make.{proj}.build
	@echo -e "\n\n\n===== $@\n"
	{sudo_make_install}$(MAKE) -C {build_proj} install
	{no_ldconfig}{sudo_ldconfig}ldconfig
	sync
	touch $@

.PHONY: {proj}
{proj}: .make.{proj}.install

.PHONY: {proj}-reinstall
{proj}-reinstall: {deps_reinstall}
	{sudo_make_install}$(MAKE) -C {build_proj} install

.PHONY: {proj}-clean
{proj}-clean:
	@echo -e "\n\n\n===== $@\n"
	-chmod -R ug+w {build_proj}
	-rm -rf {build_proj}
	-rm -rf .make.{proj}.*
'''.format(
    url=url,
    push_url=push_url or url,
    proj=proj,
    jobs=jobs,
    src=make_to_src,
    src_proj=make_to_src_proj,
    build_proj=make_to_build_proj,
    build_to_src=build_to_src,
    deps_installed=' '.join(['.make.%s.install' % d for d in deps]),
    deps_reinstall=' '.join(['%s-reinstall' %d for d in deps]),
    configure_opts=configure_opts_str,
    sudo_make_install='sudo ' if sudo_make_install else '',
    no_ldconfig='#' if no_ldconfig else '',
    sudo_ldconfig='' if ldconfig_without_sudo else 'sudo ',
    check='check' if make_check else '',
    branch=branch,
    )


projects_deps = read_projects_deps(args.projects_and_deps_file)
configure_opts = listdict()
configure_opts_files = sorted(args.configure_opts_files or [])
for configure_opts_file in configure_opts_files:
  r = read_configure_opts(configure_opts_file)
  configure_opts.extend_dict(read_configure_opts(configure_opts_file))

make_dir = args.make_dir
if not make_dir:
  deps_name = args.projects_and_deps_file.replace('.deps', '')
  opts_names = '+'.join([f.replace('.opts', '') for f in configure_opts_files])
  make_dir = 'make-%s-%s' % (deps_name, opts_names)

if not os.path.isdir(make_dir):
  os.makedirs(make_dir)

build_dir = args.build_dir
if not build_dir:
  build_dir = make_dir

output = os.path.join(make_dir, args.output)
print('Writing to %r' % output)

with open(output, 'w') as out:
  out.write('# This Makefile was generated by %s\n' % os.path.basename(sys.argv[0]))

  # convenience: add a regen target that updates the generated makefile itself
  out.write(r'''
default: all

.PHONY: all_debug
all_debug:
	$(MAKE) --dry-run -d all | grep "is newer than target"
	$(MAKE) all

# regenerate this Makefile, in case the deps or opts changed
.PHONY: regen
regen:
	{script} \
		{projects_and_deps} \
		{configure_opts} \
		-m {make_dir} \
		-o {makefile} \
		-s {src_dir} \
		-b {build_dir} \
		-u "{url}"{push_url}{sudo_make_install}{no_ldconfig}{ldconfig_without_sudo}{make_check}

'''.format(
    script=os.path.relpath(sys.argv[0], make_dir),
    projects_and_deps=os.path.relpath(args.projects_and_deps_file, make_dir),
    configure_opts=' \\\n\t\t'.join([os.path.relpath(f, make_dir) for f in configure_opts_files]),
    make_dir='.',
    makefile=args.output,
    src_dir=os.path.relpath(args.src_dir, make_dir),
    build_dir=os.path.relpath(build_dir, make_dir),
    url=args.url,
    push_url=(" \\\n\t\t-p '%s'"%args.push_url) if args.push_url else '',
    sudo_make_install=' \\\n\t\t-I' if args.sudo_make_install else '',
    no_ldconfig=' \\\n\t\t-L' if args.no_ldconfig else '',
    ldconfig_without_sudo=' \\\n\t\t--ldconfig-without-sudo' if args.ldconfig_without_sudo else '',
    make_check='' if args.make_check else " \\\n\t\t--no-make-check",
    ))

  # convenience target: clone all repositories first
  out.write('clone: \\\n\t' + ' \\\n\t'.join([ '.make.%s.clone' % p for p, d in projects_deps ]) + '\n\n')

  # convenience target: clean all
  out.write('clean: \\\n\t' + ' \\\n\t'.join([ '%s-clean' % p for p, d in projects_deps ]) + '\n\n')

  # now the actual useful build rules
  out.write('all: clone all-install\n\n')

  out.write('all-install: \\\n\t' + ' \\\n\t'.join([ '.make.%s.install' % p for p, d in projects_deps ]) + '\n\n')

  for proj, deps in projects_deps:
    all_config_opts = []
    all_config_opts.extend(configure_opts.get('ALL') or [])
    all_config_opts.extend(configure_opts.get(proj) or [])
    out.write(gen_make(proj, deps, all_config_opts, args.jobs,
                       make_dir, args.src_dir, build_dir, args.url, args.push_url,
                       args.sudo_make_install, args.no_ldconfig,
                       args.ldconfig_without_sudo, args.make_check))

# vim: expandtab tabstop=2 shiftwidth=2
