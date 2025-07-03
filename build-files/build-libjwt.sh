#!/bin/bash
#
# This script will build libJwt
# Requires build-common.sh

# Package-specific constants
RPM_PACKAGE="libjwt"

# Find build-common.sh and source it
PROJECT_DIR=`pwd`
PROJECT_PARENT=`dirname $PROJECT_DIR`
PROJECT_PP=`dirname $PROJECT_PARENT`
if [ -e $PROJECT_PP/build-server/build-common.sh ] ; then
	BUILD_SERVER_DIR=$PROJECT_PP
	source $PROJECT_PP/build-server/build-common.sh
elif [ -e /usr/libexec/curaden/build-server/build-server/build-common.sh ] ; then
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

pushd $CHECKOUT_DIR

# Get latest tag
LIBJWT_VERSION=$(curl --silent https://api.github.com/repos/benmcollins/libjwt/tags | jq '.[].name' | sed 's/"//g' | sed 's/^v//' | sort -rV | head -1)
LIBJWT_RELEASE="1.$EL_VERSION"
SPUTNIK_REPO_NAME="curaden-repack-$EL_VERSION"

# Check which is the latest version we aleady have
find_package $SPUTNIK_REPO_NAME $RPM_PACKAGE $LIBJWT_VERSION $LIBJWT_RELEASE
if [ $? -eq 1 ] ; then
	popd
	print_notice "Package $RPM_PACKAGE version $LIBJWT_VERSION release $LIBJWT_RELEASE already exists in repo $SPUTNIK_REPO_NAME"
	happy_end
fi

# Get library version
ARG_RPM_VERSION=$LIBJWT_VERSION
LIBJWT_FILENAME="libjwt-$LIBJWT_VERSION.tar.gz"
wget -O $LIBJWT_FILENAME "https://github.com/benmcollins/libjwt/archive/v$LIBJWT_VERSION.tar.gz"

popd

SPEC_FILE_NAME="libjwt.spec"
copy_spec_file

# Copy package sources
mv $CHECKOUT_DIR/$LIBJWT_FILENAME $RPM_HOME/SOURCES

# Build the RPM and SRPM
RPMBUILD_ARGS=("_libjwt_version $LIBJWT_VERSION" "_libjwt_release $LIBJWT_RELEASE")
build_rpms

# Declare we're good
happy_end

