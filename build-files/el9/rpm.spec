# CDN Nginx module

# Version and Release should come from command line, e.g.: --define '_cdn_version 0.32.0' --define '_cdn_release 1'
# If they do not, assume some generic defaults
%{!?_cdn_version:%define _cdn_version 0.0.0}
%{!?_cdn_release:%define _cdn_release 0}

Summary: CDN Nginx module
Name: %{_cdn_name}
Version: %{_cdn_version}
%if "%{?dist:%{dist}}%{!?dist:0}" == ".rel"
Release: %{_cdn_release}%{?dist}.el%{rhel}
%else
Release: 0.%{_cdn_release}%{?dist}.el%{rhel}
%endif
URL: http://www.zavedil.com
Packager: Assen Totin <assen.totin@gmail.com>
Group: Applications
License: Proprietary
BuildArch: x86_64
BuildRequires: libbson-devel, libcurl-devel, libxml2-devel, libxslt-devel, gd-devel, perl-ExtUtils-Embed, gcc, make
#BuildRequires: libjwt-devel
#BuildRequires: mongo-c-driver-devel
#BuildRequires: mariadb-connector-c-devel
#BuildRequires: ocilib-devel
#BuildRequires: libpq-devel
#BuldRequires: hiredis-devel
Requires: nginx, libcurl, libbson, libxml2
#Requires: libjwt
#Requires: mongo-c-driver
#Requires: mariadb-connector-c
#Requires: ocilib
#Requires: libpq
#Requires: hiredis

%description
CDN Nginx module

%prep

%build

%install

mkdir -p $RPM_BUILD_ROOT/etc/cdn/index.d
cp -r ${RPM_SOURCE_DIR}/config-files/index* $RPM_BUILD_ROOT/etc/cdn/index.d
mkdir -p $RPM_BUILD_ROOT/etc/cdn/mirror.d
cp -r ${RPM_SOURCE_DIR}/config-files/mirror* $RPM_BUILD_ROOT/etc/cdn/mirror.d

mkdir -p $RPM_BUILD_ROOT/etc/cron.d
cp -r ${RPM_SOURCE_DIR}/support-files/cron/* $RPM_BUILD_ROOT/etc/cron.d

mkdir -p $RPM_BUILD_ROOT/usr/share/nginx/modules
cp -r ${RPM_SOURCE_DIR}/support-files/nginx/modules/* $RPM_BUILD_ROOT/usr/share/nginx/modules

mkdir -p $RPM_BUILD_ROOT/usr/lib64/nginx/modules
cp -r ${RPM_SOURCE_DIR}/lib/* $RPM_BUILD_ROOT/usr/lib64/nginx/modules

mkdir -p $RPM_BUILD_ROOT/usr/bin
cp -r ${RPM_SOURCE_DIR}/bin/* $RPM_BUILD_ROOT/usr/bin

mkdir -p $RPM_BUILD_ROOT/var/lib/cdn/mirror.d

%clean
rm -rf $RPM_BUILD_ROOT $RPM_BUILD_DIR

%files

%defattr(-, root, root)

/etc/cdn

/etc/cron.d/*

/usr/share/nginx/modules/*
/usr/lib64/nginx/modules/*

/var/lib/cdn

%defattr(755, root, root)
/usr/bin/*

%pre

%post

systemctl restart nginx
systemctl restart crond

%preun

%postun

# NB: Changelog records the changes in this spec file. For changes in the packaged product, use the ChangeLog file.
%changelog
* Mon Jul 1 2019 Assen Totin <assen.totin@gmail.com>
- Release 0.0.1

