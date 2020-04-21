# CDN Nginx module

# Version and Release should come from command line, e.g.: --define '_cdn_version 0.32.0' --define '_cdn_release 1'
# If they do not, assume some generic defaults
%{!?_cdn_version:%define _cdn_version 0.0.0}
%{!?_cdn_release:%define _cdn_release 0}

Summary: CDN Nginx module
Name: cdn-nginx
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
BuildRequires: libbson-devel, libcurl-devel
#BuildRequires: libjwt-devel
#BuildRequires: mariadb-devel
#BuildRequires: ocilib-devel
Requires: nginx, libcurl, libbson
#Requires: libjwt
#Requires: mariadb-libs
#Requires: ocilib

%description
CDN Nginx module

%prep

%build

%install

mkdir -p $RPM_BUILD_ROOT/usr/share/nginx/modules
cp -r ${RPM_SOURCE_DIR}/support-files/nginx/modules/* $RPM_BUILD_ROOT/usr/share/nginx/modules

mkdir -p $RPM_BUILD_ROOT/usr/lib64/nginx/modules
cp -r ${RPM_SOURCE_DIR}/lib/* $RPM_BUILD_ROOT/usr/lib64/nginx/modules

mkdir -p $RPM_BUILD_ROOT/usr/bin
cp -r ${RPM_SOURCE_DIR}/tools/* $RPM_BUILD_ROOT/usr/bin

%clean
rm -rf $RPM_BUILD_ROOT $RPM_BUILD_DIR

%files
%defattr(-, root, root)
/usr/share/nginx/modules/*
/usr/lib64/nginx/modules/*

%defattr(755, root, root)
/usr/bin/*

%pre

%post

%preun

%postun

# NB: Changelog records the changes in this spec file. For changes in the packaged product, use the ChangeLog file.
%changelog
* Mon Jul 1 2019 Assen Totin <assen.totin@gmail.com>
- Release 0.0.1

