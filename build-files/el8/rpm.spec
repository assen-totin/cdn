# Medicloud CDN Nginx module

# Version and Release should come from command line, e.g.: --define '_curaden_version 0.32.0' --define '_curaden_release 1'
# If they do not, assume some generic defaults
%{!?_curaden_version:%define _curaden_version 0.0.0}
%{!?_curaden_release:%define _curaden_release 0}

Summary: Medicloud CDN Nginx module
Name: curaden-medicloud-cdn-nginx
Version: %{_curaden_version}
%if "%{?dist:%{dist}}%{!?dist:0}" == ".rel"
Release: %{_curaden_release}%{?dist}.el%{rhel}
%else
Release: 0.%{_curaden_release}%{?dist}.el%{rhel}
%endif
Vendor: Curaden
URL: http://www.curaden.com
Packager: Curaden AG <technik@curaden.ch>
Group: Curaden
License: Proprietary
BuildArch: x86_64
Requires: nginx, libcurl, libbson

%description
Medicloud CDN Nginx module

%prep

%build

%install

mkdir -p $RPM_BUILD_ROOT/usr/share/nginx/modules
cp -r ${RPM_SOURCE_DIR}/support-files/nginx/modules/* $RPM_BUILD_ROOT/usr/share/nginx/modules

mkdir -p $RPM_BUILD_ROOT/usr/lib64/nginx/modules
cp -r ${RPM_SOURCE_DIR}/lib/* $RPM_BUILD_ROOT/usr/lib64/nginx/modules

%clean
rm -rf $RPM_BUILD_ROOT $RPM_BUILD_DIR

%files
%defattr(-, root, root)
/usr/share/nginx/modules/*
/usr/lib64/nginx/modules/*

%pre

%post
# Dono trestart Nginx as this module requries manual configuration
#systemctl restart nginx

%preun

%postun

# NB: Changelog records the changes in this spec file. For changes in the packaged product, use the ChangeLog file.
%changelog
* Mon Jul 1 2019 Curaden <technik@curaden.ch>
- Release 0.0.1

