Name: makedumpfile
Summary: makedumpfile package
Version: 1.7.8
Release: 1
Group: Applications/Text
License: GPL
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-root
Distribution: Linux 2.6 or greater
Packager: The makedumpfile team <https://github.com/makedumpfile>
ExclusiveOS: Linux
ExclusiveArch: i386 ia64 ppc ppc64 ppc64pseries ppc64iseries x86_64
Buildroot: %{_tmppath}/%{name}-root
BuildRequires: zlib-devel elfutils-devel

%description
makedumpfile package.

%prep
%setup

%build
make LINKTYPE=dynamic

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/sbin
mkdir -p %{buildroot}/usr/share/man/man5
mkdir -p %{buildroot}/usr/share/man/man8
mkdir -p %{buildroot}/usr/share/%{name}-%{version}/eppic-scripts/
make install DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}

%files
/usr/sbin/makedumpfile
/usr/sbin/makedumpfile-R.pl
/usr/share/man/man5/makedumpfile.conf.5.gz
/usr/share/man/man8/makedumpfile.8.gz
/usr/share/%{name}-%{version}/makedumpfile.conf.sample
/usr/share/%{name}-%{version}/eppic_scripts/

%changelog
* Wed Dec 18 2013 Atsushi Kumagai <kumagai-atsushi@mxc.nes.nec.co.jp>
- reflect the changing of installation directory.

* Thu Aug 21 2008 Ken'ichi Ohmichi <oomichi@mxs.nes.nec.co.jp>
- initial release.
