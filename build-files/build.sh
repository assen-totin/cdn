#!/bin/bash
#
# This script will build Curaden Setup utility
# Requires build-common.sh

# Declare job-specific command-line options
CMDL_JOB_NAME=()
CMDL_JOB_FLAG=()
CMDL_JOB_HELP=()

CMDL_JOB_NAME+=("--nginx-version")
CMDL_JOB_FLAG+=(1)
CMDL_JOB_HELP+=("The version of Nginx to build for")

CMDL_JOB_NAME+=("--cdn-enable-jwt")
CMDL_JOB_FLAG+=(0)
CMDL_JOB_HELP+=("Link against libjwt.so")

CMDL_JOB_NAME+=("--cdn-enable-mongo")
CMDL_JOB_FLAG+=(0)
CMDL_JOB_HELP+=("Link against Mongo C driver")

CMDL_JOB_NAME+=("--cdn-enable-mysql")
CMDL_JOB_FLAG+=(0)
CMDL_JOB_HELP+=("Link against libmysqlclient.so")

CMDL_JOB_NAME+=("--cdn-enable-postgresql")
CMDL_JOB_FLAG+=(0)
CMDL_JOB_HELP+=("Link against libpq.so")

CMDL_JOB_NAME+=("--cdn-enable-redis")
CMDL_JOB_FLAG+=(0)
CMDL_JOB_HELP+=("Link against libhiredis.so")

CMDL_JOB_NAME+=("--cdn-enable-oracle")
CMDL_JOB_FLAG+=(0)
CMDL_JOB_HELP+=("Link against Oracle wrapper liboci.so")

CMDL_JOB_NAME+=("--cdn-oracle-home")
CMDL_JOB_FLAG+=(1)
CMDL_JOB_HELP+=("ORACLE_HOME directory")

# Package-specific constants
RPM_PACKAGE="nginx-cdn"
[ x$ARG_RPM_PACKAGE != 'x' ] && RPM_PACKAGE=$ARG_RPM_PACKAGE

# Find build-common.sh and source it
CURR_DIR=`pwd`
PROJECT_DIR=`dirname $CURR_DIR`
if [ -e /usr/libexec/curaden/build-server ] ; then
	BUILD_SERVER_DIR=/usr/libexec/curaden/build-server
	source $BUILD_SERVER_DIR/build-server/build-common.sh
else
	echo "ERROR: Unable to find build-common.sh"
	exit 1;
fi

# Call the common entry point
build_common $@

# Check out proper version
git_checkout

# Go to checkout dir
pushd $CHECKOUT_DIR

# Extra libraries needed by this modules
EXTRA_LIBS="-lbson-1.0 -lcurl -lxml2"
EXTRA_INCLUDES="-I /usr/include/libbson-1.0 -I/usr/include/libxml2"
if [ x$ARG_CDN_ENABLE_JWT != 'x' ] ; then
	EXTRA_LIBS="$EXTRA_LIBS -ljwt"
	sed -i 's|^.*CDN_ENABLE_JWT.*$|#define CDN_ENABLE_JWT|' src/modules.h
fi
if [ x$ARG_CDN_ENABLE_MONGO != 'x' ] ; then
	EXTRA_LIBS="$EXTRA_LIBS -lmongoc-1.0"
	EXTRA_INCLUDES="$EXTRA_INCLUDES -I /usr/include/libmongoc-1.0"
	sed -i 's|^.*CDN_ENABLE_MONGO.*$|#define CDN_ENABLE_MONGO|' src/modules.h
fi
if [ x$ARG_CDN_ENABLE_MYSQL != 'x' ] ; then
	[ x$EL_VERSION == 'xel7' ] && EXTRA_LIBS="$EXTRA_LIBS -L/usr/lib64/mysql"
	EXTRA_LIBS="$EXTRA_LIBS -lmysqlclient"
	EXTRA_INCLUDES="$EXTRA_INCLUDES -I /usr/include/mysql"
	sed -i 's|^.*CDN_ENABLE_MYSQL.*$|#define CDN_ENABLE_MYSQL|' src/modules.h
fi
if [ x$ARG_CDN_ENABLE_POSTGRESQL != 'x' ] ; then
	EXTRA_LIBS="$EXTRA_LIBS -lpq"
	sed -i 's|^.*CDN_ENABLE_POSTGRESQL.*$|#define CDN_ENABLE_POSTGRESQL|' src/modules.h
fi
if [ x$ARG_CDN_ENABLE_ORACLE != 'x' ] ; then
	export LD_LIBRARY_PATH=$ARG_CDN_ENABLE_ORACLE_HOME/lib
	EXTRA_LIBS="$EXTRA_LIBS -locilib"
	sed -i 's|^.*CDN_ENABLE_ORACLE.*$|#define CDN_ENABLE_ORACLE|' src/modules.h
fi
if [ x$ARG_CDN_ENABLE_REDIS != 'x' ] ; then
	EXTRA_INCLUDES="$EXTRA_INCLUDES -I /usr/include/hiredis"
	EXTRA_LIBS="$EXTRA_LIBS -lhiredis"
	sed -i 's|^.*CDN_ENABLE_REDIS.*$|#define CDN_ENABLE_REDIS|' src/modules.h
fi

# Download the Nginx source
wget http://nginx.org/download/nginx-$ARG_NGINX_VERSION.tar.gz
gunzip nginx-$ARG_NGINX_VERSION.tar.gz
tar xf nginx-$ARG_NGINX_VERSION.tar

# Build the module
mkdir lib
cd nginx-$ARG_NGINX_VERSION

if [ x$EL_VERSION == 'xel7' ] ; then
	CFLAGS=-Wno-error ./configure --add-dynamic-module=../src --prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --pid-path=/run/nginx.pid --lock-path=/run/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-stream_ssl_preread_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-http_auth_request_module --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-google_perftools_module --with-debug --with-cc-opt="-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -m64 -mtune=generic $EXTRA_INCLUDES" --with-ld-opt="-Wl,-z,relro -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E $EXTRA_LIBS"
fi

# For EL8, we need to apply one of the patches from the source RPM first or code will not build
if [ x$EL_VERSION == 'xel8' ] ; then
	patch -p1 < ../patches/0001*
	CFLAGS=-Wno-error ./configure --add-dynamic-module=../src --prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --pid-path=/run/nginx.pid --lock-path=/run/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-http_auth_request_module --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-debug --with-cc-opt="-O2 -g -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fexceptions -fstack-protector-strong -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1 -m64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection $EXTRA_INCLUDES" --with-ld-opt="-Wl,-z,relro -Wl,-z,now -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E $EXTRA_LIBS"
fi

[ $? -gt 0 ] && print_error "Configure command failed."
make modules
[ $? -gt 0 ] && print_error "Make modules command failed."
cp objs/ngx_http_cdn_module.so ../lib
cd ..

popd

# Copy files
cp -r $CHECKOUT_DIR/lib $RPM_HOME/SOURCES
cp -r $CHECKOUT_DIR/support-files $RPM_HOME/SOURCES
cp -r $CHECKOUT_DIR/tools $RPM_HOME/SOURCES

# Copy the appropriate spec file for the build
copy_spec_file

# Update RPM dependencies
if [ x$ARG_CDN_ENABLE_JWT != 'x' ] ; then
	sed -i 's|^.*libjwt-devel.*$|BuildRequires: libjwt-devel|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
	sed -i 's|^.*libjwt$|Requires: libjwt|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
fi
if [ x$ARG_CDN_ENABLE_MONGO != 'x' ] ; then
	sed -i 's|^.*mongo-c-driver-devel.*$|BuildRequires: mongo-c-driver-devel|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
	sed -i 's|^.*mongo-c-driver$|Requires: mongo-c-driver|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
fi
if [ x$ARG_CDN_ENABLE_MYSQL != 'x' ] ; then
	if [ x$EL_VERSION == 'xel7' ] ; then
		sed -i 's|^.*mariadb-devel.*$|BuildRequires: mariadb-devel|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
		sed -i 's|^.*mariadb-libs.*$|Requires: mariadb-libs|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
	fi
	if [ x$EL_VERSION == 'xel8' ] ; then
		sed -i 's|^.*BuildRequires: mariadb-connector-c-devel.*$|BuildRequires: mariadb-connector-c-devel|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
		sed -i 's|^.*Requires: mariadb-connector-c-devel.*$|Requires: mariadb-connector-c-devel|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
	fi
fi
if [ x$ARG_CDN_ENABLE_POSTGRESQL != 'x' ] ; then
	if [ x$EL_VERSION == 'xel7' ] ; then
		sed -i 's|^.*BuildRequires: postgresql-devel.*$|BuildRequires: postgresql-devel|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
		sed -i 's|^.*Requires: postgresql.*$|Requires: postgresql|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
	fi
	if [ x$EL_VERSION == 'xel8' ] ; then
		sed -i 's|^.*BuildRequires: libpq-devel.*$|BuildRequires: libpq-devel|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
		sed -i 's|^.*Requires: libpq.*$|Requires: libpq|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
	fi
fi
if [ x$ARG_CDN_ENABLE_ORACLE != 'x' ] ; then
	sed -i 's|^.*ocilib-devel.*$|BuildRequires: ocilib-devel|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
	sed -i 's|^.*ocilib$|Requires: ocilib|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
fi
if [ x$ARG_CDN_ENABLE_REDIS != 'x' ] ; then
	sed -i 's|^.*hiredis-devel.*$|BuildRequires: hiredis-devel|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
	sed -i 's|^.*Requires: hiredis.$|Requires: hiredis|' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
fi

# Build the RPM and SRPM
RPMBUILD_ARGS=("_cdn_name $RPM_PACKAGE" "_cdn_version $ARG_RPM_VERSION" "_cdn_release $RPM_RELEASE")
build_rpms

# Declare we're good
happy_end

