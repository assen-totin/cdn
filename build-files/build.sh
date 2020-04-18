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

CMDL_JOB_NAME+=("--cdn-enable-mysql")
CMDL_JOB_FLAG+=(0)
CMDL_JOB_HELP+=("Link against libmysqlclient.so")

CMDL_JOB_NAME+=("--cdn-enable-oracle")
CMDL_JOB_FLAG+=(0)
CMDL_JOB_HELP+=("Link against Oracle wrapper liboci.so")

# Package-specific constants
RPM_PACKAGE="curaden-medicloud-cdn-nginx"

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

# Configure extra build agruments
if [ x$ARG_CDN_ENABLE_JWT != 'x' ] ; then
	EXTRA_LIBS="$EXTRA_LIBS -ljwt"
fi
if [ x$ARG_CDN_ENABLE_MYSQL != 'x' ] ; then
	EXTRA_INCLUDES="$EXTRA_INCLUDES -I /usr/include/mysql"
	EXTRA_LIBS="$EXTRA_LIBS -lmysqlclient"
fi
if [ x$ARG_CDN_ENABLE_ORACLE != 'x' ] ; then
	EXTRA_LIBS="$EXTRA_LIBS -locilib"
fi

# Download the Nginx source
wget http://nginx.org/download/nginx-$ARG_NGINX_VERSION.tar.gz
gunzip nginx-$ARG_NGINX_VERSION.tar.gz
tar xf nginx-$ARG_NGINX_VERSION.tar

# Build the module
mkdir lib
cd nginx-$ARG_NGINX_VERSION

if [ xEL_VERSION == 'x8' ] ; then
	CFLAGS=-Wno-error ./configure --add-dynamic-module=../src --prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --pid-path=/run/nginx.pid --lock-path=/run/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-stream_ssl_preread_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-http_auth_request_module --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-google_perftools_module --with-debug --with-cc-opt="-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -m64 -mtune=generic -I /usr/include/libbson-1.0 $EXTRA_INCLUDES" --with-ld-opt="-Wl,-z,relro -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E -lbson-1.0 -lcurl $EXTRA_LIBS"
fi

# For EL8, we need to apply one of the patches from the source RPM first or code will not build
if [ xEL_VERSION == 'x8' ] ; then
	patch -p1 < ../patches/0001*
	CFLAGS=-Wno-error ./configure --add-dynamic-module=../src --prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --pid-path=/run/nginx.pid --lock-path=/run/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-http_auth_request_module --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-debug --with-cc-opt="-O2 -g -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fexceptions -fstack-protector-strong -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -specs=/usr/lib/rpm/redhat/redhat-annobin-cc1 -m64 -mtune=generic -fasynchronous-unwind-tables -fstack-clash-protection -fcf-protection -I /usr/include/libbson-1.0 $EXTRA_INCLUDES" --with-ld-opt="-Wl,-z,relro -Wl,-z,now -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E -lbson-1.0 -lcurl $EXTRA_LIBS"
fi

[ $? -gt 0 ] && print_error "Configure command failed."
make modules
[ $? -gt 0 ] && print_error "Make modules command failed."
cp objs/ngx_http_medicloud_module.so ../lib
cd ..

popd

# Copy files
cp -r $CHECKOUT_DIR/lib $RPM_HOME/SOURCES
cp -r $CHECKOUT_DIR/support-files $RPM_HOME/SOURCES
cp -r $CHECKOUT_DIR/tools $RPM_HOME/SOURCES

# Copy the appropriate spec file for the build
copy_spec_file

# Configure extra runtime deps
if [ x$ARG_CDN_ENABLE_JWT != 'x' ]; then
	sed -i 's/#BuildRequires: libjwt-devel/BuildRequires: libjwt-devel/' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
	sed -i 's/#Requires: libjwt/Requries: libjwt/' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
fi
if [ x$ARG_CDN_ENABLE_MYSQL != 'x' ] ; then
	# EL7
	sed -i 's/#BuildRequires: mariadb-devel/Requries: mariadb-devel/' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
	sed -i 's/#Requires: mariadb-libs/Requries: mariadb-libs/' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
	# EL8
	sed -i 's/#BuildRequires: mariadb-connector-c-devel/BuildRequires: mariadb-connector-c-devel/' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
	sed -i 's/#Requires: mariadb-connector-c-devel/Requries: mariadb-connector-c-devel/' $RPM_HOME/SPECS/$RPM_PACKAGE.spec

fi
if [ x$ARG_CDN_ENABLE_ORACLE != 'x' ] ; then
	sed -i 's/#BuildRequires: ocilib-devel/BuildRequires: ocilib-devel/' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
	sed -i 's/#Requires: ocilib/Requries: ocilib/' $RPM_HOME/SPECS/$RPM_PACKAGE.spec
fi

# Build the RPM and SRPM
build_rpms

# Declare we're good
happy_end

