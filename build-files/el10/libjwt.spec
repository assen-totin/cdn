Name: libjwt
Version: %{_libjwt_version}
Release: %{_libjwt_release}
Summary:	JSON Web Tokens C library
Group:		Development/Libraries
License:	MPLv2
URL:		https://github.com/benmcollins/libjwt
Source0:	%{name}-%{version}.tar.gz
BuildRequires:  cmake
BuildRequires:  jansson-devel
BuildRequires:  openssl-devel
BuildRequires:  check-devel
#BuildRequires:  rpmlint
Requires:       jansson
Requires:       openssl

%description
JSON Web Tokens C library (see jwt.io)

%package devel
Summary:        Header files and libraries for JSON Web Tokens C library
Requires: 	libjwt

%description devel
Header files and libraries needed to develop programs that use the
JSON Web Tokens C library.

%prep
%setup -q

%build
mkdir build
cd build
CFLAGS=-Wno-error cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make
make DESTDIR=%{buildroot} install
rm -rf %{buildroot}/usr/lib/cmake
rm -rf %{buildroot}/usr/share

%files
%defattr(-,root,root)
%doc LICENSE README.md
/usr/bin/*
/usr/lib/*.so.*
/usr/lib/*.so

%files devel
%defattr(-,root,root)
/usr/include/*h
/usr/lib/*.a
/usr/lib/pkgconfig/*

%changelog
* Wed Sep 19 2018 Gavin Carr <gavin@openfusion.com.au> - 1.9.0-1
- Initial package.

