AC_INIT(scd-pkcs11, 0.0, , , https://github.com/sektioneins/scd-pkcs11)

AC_CONFIG_FILES([Makefile])

AC_MSG_CHECKING([SSL support])

AC_ARG_WITH([ssl],
	[AS_HELP_STRING([--with-ssl],
		[use openssl/libressl @<:@default=yes@:>@])],
	[],
	[])

if test "$with_ssl" != "no" ; then
	extra_CFLAGS="-DHAVE_SSL"
	extra_LDFLAGS="-lssl -lcrypto"
	if test -n "$with_ssl" -a "$with_ssl" != "yes" ; then
		extra_CFLAGS="$extra_CFLAGS -I$with_ssl/include"
		extra_LDFLAGS="$extra_LDFLAGS -L$with_ssl/lib"
	fi
	with_ssl=yes
fi

AC_MSG_RESULT([$with_ssl])


AC_MSG_CHECKING([libassuan])
AC_ARG_WITH([assuan],
	[AS_HELP_STRING([--with-assuan],
		[libassuan-config path])],
	[
		if test "$with_assuan" == "no"; then
			AC_MSG_ERROR([libassuan is required!])
		fi
		libassuan_path="$with_assuan/"
		with_assuan=yes
	],
	[with_assuan=yes])

extra_CFLAGS="$extra_CFLAGS \$(shell ${libassuan_path}libassuan-config --cflags)"
extra_LDFLAGS="$extra_LDFLAGS \$(shell ${libassuan_path}libassuan-config --libs)"

AC_MSG_RESULT([$with_assuan])


AC_MSG_CHECKING([libgcrypt])
AC_ARG_WITH([gcrypt],
	[AS_HELP_STRING([--with-gcrypt],
		[libgcrypt-config path])],
	[
		if test "$with_gcrypt" == "no"; then
			AC_MSG_ERROR([libgcrypt is required!])
		fi
		libgcrypt_path="$with_gcrypt/"
		with_gcrypt=yes
	],
	[with_gcrypt=yes])

extra_CFLAGS="$extra_CFLAGS \$(shell ${libgcrypt_path}libgcrypt-config --cflags)"
extra_LDFLAGS="$extra_LDFLAGS \$(shell ${libgcrypt_path}libgcrypt-config --libs)"

AC_MSG_RESULT([$with_gcrypt])



AC_SUBST([extra_CFLAGS], [$extra_CFLAGS])
AC_SUBST([extra_LDFLAGS], [$extra_LDFLAGS])


AC_OUTPUT
