Name: makedumpfile
Summary: makedumpfile package
Version: 1.3.4
Release: 1
Group: Applications/Text
License: GPL
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-root
Distribution: Linux 2.6 or greater
Packager: Ken'ichi Ohmichi <oomichi@mxs.nes.nec.co.jp>
ExclusiveOS: Linux
ExclusiveArch: i386 ia64 ppc ppc64 ppc64pseries ppc64iseries x86_64
Buildroot: %{_tmppath}/%{name}-root
BuildRequires: zlib-devel elfutils-devel-static

%description
makedumpfile package.

%prep
%setup

%build
make

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/bin
mkdir -p %{buildroot}/usr/share/man/man8
make install DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}

%files
/bin/makedumpfile
/bin/makedumpfile-R.pl
/usr/share/man/man8/makedumpfile.8.gz

%changelog
* Fri Aug 21 2008 Ken'ichi Ohmichi <oomichi@mxs.nes.nec.co.jp>
- initial release.

