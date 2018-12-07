$gpg_inst = "C:/Program Files (x86)/GnuPG"
$includes = @("-I${gpg_inst}/include")
$cflags = @("-DSEC_DEBUG", "-DSEC_LOG_STDERR", "-std=gnu99")
echo "."
& gcc -c sec.c $includes $cflags
echo "."
& gcc -c scd.c $includes $cflags
echo "."
& gcc -c pkcs11-impl.c $includes $cflags
echo "."
& gcc sec.o scd.o pkcs11-impl.o -shared -o scd-pkcs11.dll -v "-L${gpg_inst}/bin" -lassuan-0 -lgcrypt-20 -lgpg-error-0

