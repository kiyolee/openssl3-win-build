setlocal

set OPENSSL_VER=3.6.0
set OPENSSL_VER_SED=3\.6\.0
set OPENSSL_BASE=openssl-%OPENSSL_VER%
set OPENSSL_BASE_SED=openssl-%OPENSSL_VER_SED%
set OPENSSL_DIR=..\%OPENSSL_BASE%
set OPENSSL_DIR_SED=\.\.\\\\openssl-%OPENSSL_VER_SED%

set ZLIB_DIR=..\zlib

set _GEN_LIST_INCL=^
  include\crypto\bn_conf.h ^
  include\crypto\dso_conf.h ^
  include\openssl\asn1.h ^
  include\openssl\asn1t.h ^
  include\openssl\bio.h ^
  include\openssl\cmp.h ^
  include\openssl\cms.h ^
  include\openssl\comp.h ^
  include\openssl\conf.h ^
  include\openssl\configuration.h ^
  include\openssl\crmf.h ^
  include\openssl\crypto.h ^
  include\openssl\ct.h ^
  include\openssl\err.h ^
  include\openssl\ess.h ^
  include\openssl\fipskey.h ^
  include\openssl\lhash.h ^
  include\openssl\ocsp.h ^
  include\openssl\opensslv.h ^
  include\openssl\pkcs12.h ^
  include\openssl\pkcs7.h ^
  include\openssl\safestack.h ^
  include\openssl\srp.h ^
  include\openssl\ssl.h ^
  include\openssl\ui.h ^
  include\openssl\x509.h ^
  include\openssl\x509_acert.h ^
  include\openssl\x509_vfy.h ^
  include\openssl\x509v3.h

set _GEN_LIST_PARAMNAMES_INCL=^
  include\openssl\core_names.h

set _GEN_LIST_PARAMNAMES_CSRC=^
  providers\implementations\asymciphers\rsa_enc.c ^
  providers\implementations\asymciphers\sm2_enc.c ^
  providers\implementations\ciphers\cipher_chacha20_poly1305.c ^
  providers\implementations\ciphers\ciphercommon.c ^
  providers\implementations\ciphers\ciphercommon_ccm.c ^
  providers\implementations\ciphers\ciphercommon_gcm.c ^
  providers\implementations\digests\blake2_prov.c ^
  providers\implementations\digests\digestcommon.c ^
  providers\implementations\digests\sha3_prov.c ^
  providers\implementations\encode_decode\decode_der2key.c ^
  providers\implementations\encode_decode\decode_epki2pki.c ^
  providers\implementations\encode_decode\decode_pem2der.c ^
  providers\implementations\encode_decode\decode_pvk2key.c ^
  providers\implementations\encode_decode\decode_spki2typespki.c ^
  providers\implementations\encode_decode\encode_key2any.c ^
  providers\implementations\encode_decode\encode_key2ms.c ^
  providers\implementations\exchange\dh_exch.c ^
  providers\implementations\exchange\ecdh_exch.c ^
  providers\implementations\exchange\ecx_exch.c ^
  providers\implementations\kdfs\argon2.c ^
  providers\implementations\kdfs\hkdf.c ^
  providers\implementations\kdfs\hmacdrbg_kdf.c ^
  providers\implementations\kdfs\kbkdf.c ^
  providers\implementations\kdfs\krb5kdf.c ^
  providers\implementations\kdfs\pbkdf1.c ^
  providers\implementations\kdfs\pbkdf2.c ^
  providers\implementations\kdfs\pkcs12kdf.c ^
  providers\implementations\kdfs\pvkkdf.c ^
  providers\implementations\kdfs\scrypt.c ^
  providers\implementations\kdfs\sshkdf.c ^
  providers\implementations\kdfs\sskdf.c ^
  providers\implementations\kdfs\tls1_prf.c ^
  providers\implementations\kdfs\x942kdf.c ^
  providers\implementations\kem\ec_kem.c ^
  providers\implementations\kem\ecx_kem.c ^
  providers\implementations\kem\ml_kem_kem.c ^
  providers\implementations\kem\rsa_kem.c ^
  providers\implementations\keymgmt\ecx_kmgmt.c ^
  providers\implementations\keymgmt\lms_kmgmt.c ^
  providers\implementations\keymgmt\ml_dsa_kmgmt.c ^
  providers\implementations\keymgmt\ml_kem_kmgmt.c ^
  providers\implementations\keymgmt\mlx_kmgmt.c ^
  providers\implementations\keymgmt\slh_dsa_kmgmt.c ^
  providers\implementations\keymgmt\template_kmgmt.c ^
  providers\implementations\macs\cmac_prov.c ^
  providers\implementations\macs\gmac_prov.c ^
  providers\implementations\macs\hmac_prov.c ^
  providers\implementations\macs\kmac_prov.c ^
  providers\implementations\macs\poly1305_prov.c ^
  providers\implementations\macs\siphash_prov.c ^
  providers\implementations\rands\drbg_ctr.c ^
  providers\implementations\rands\drbg_hash.c ^
  providers\implementations\rands\drbg_hmac.c ^
  providers\implementations\rands\fips_crng_test.c ^
  providers\implementations\rands\seed_src.c ^
  providers\implementations\rands\seed_src_jitter.c ^
  providers\implementations\rands\test_rng.c ^
  providers\implementations\signature\dsa_sig.c ^
  providers\implementations\signature\ecdsa_sig.c ^
  providers\implementations\signature\eddsa_sig.c ^
  providers\implementations\signature\ml_dsa_sig.c ^
  providers\implementations\signature\rsa_sig.c ^
  providers\implementations\signature\slh_dsa_sig.c ^
  providers\implementations\signature\sm2_sig.c ^
  providers\implementations\skeymgmt\generic.c ^
  providers\implementations\storemgmt\file_store.c ^
  providers\implementations\storemgmt\file_store_any2obj.c ^
  providers\implementations\storemgmt\winstore_store.c

set _GEN_LIST_PROV_INCL=^
  providers\common\include\prov\der_digests.h ^
  providers\common\include\prov\der_dsa.h ^
  providers\common\include\prov\der_ec.h ^
  providers\common\include\prov\der_ecx.h ^
  providers\common\include\prov\der_hkdf.h ^
  providers\common\include\prov\der_ml_dsa.h ^
  providers\common\include\prov\der_rsa.h ^
  providers\common\include\prov\der_slh_dsa.h ^
  providers\common\include\prov\der_sm2.h ^
  providers\common\include\prov\der_wrap.h ^
  providers\implementations\include\prov\blake2_params.inc

set _GEN_LIST_PROV_CSRC=^
  providers\common\der\der_digests_gen.c ^
  providers\common\der\der_dsa_gen.c ^
  providers\common\der\der_ec_gen.c ^
  providers\common\der\der_ecx_gen.c ^
  providers\common\der\der_hkdf_gen.c ^
  providers\common\der\der_ml_dsa_gen.c ^
  providers\common\der\der_rsa_gen.c ^
  providers\common\der\der_slh_dsa_gen.c ^
  providers\common\der\der_sm2_gen.c ^
  providers\common\der\der_wrap_gen.c

set _GEN_LIST=^
  %_GEN_LIST_INCL% ^
  %_GEN_LIST_PARAMNAMES_INCL% ^
  %_GEN_LIST_PARAMNAMES_CSRC% ^
  %_GEN_LIST_PROV_INCL% ^
  %_GEN_LIST_PROV_CSRC% ^
  apps\progs.c apps\progs.h ^
  apps\CA.pl apps\tsget.pl tools\c_rehash.pl util\wrap.pl

mkdir dll64
mkdir lib64
mkdir dll32
mkdir lib32
mkdir dllarm64
mkdir libarm64
mkdir dllarm32
mkdir libarm32

pushd dll64
perl %OPENSSL_DIR%\Configure --prefix="%ProgramFiles%\OpenSSL-3" --with-zlib-include=%ZLIB_DIR% --with-zlib-lib=%ZLIB_DIR%\build\x64\Release\libz-static.lib VC-WIN64A-masm no-dynamic-engine zlib
call :genfile
call :clndir
popd

pushd lib64
perl %OPENSSL_DIR%\Configure --prefix="%ProgramFiles%\OpenSSL-3" --with-zlib-include=%ZLIB_DIR% --with-zlib-lib=%ZLIB_DIR%\build\x64\Release\libz-static.lib VC-WIN64A-masm no-shared no-dynamic-engine zlib
call :genfile
call :clndir
popd

pushd dll32
perl %OPENSSL_DIR%\Configure --prefix="%ProgramFiles(x86)%\OpenSSL-3" --with-zlib-include=%ZLIB_DIR% --with-zlib-lib=%ZLIB_DIR%\build\Release\libz-static.lib VC-WIN32 no-dynamic-engine zlib
call :genfile
call :clndir
popd

pushd lib32
perl %OPENSSL_DIR%\Configure --prefix="%ProgramFiles(x86)%\OpenSSL-3" --with-zlib-include=%ZLIB_DIR% --with-zlib-lib=%ZLIB_DIR%\build\Release\libz-static.lib VC-WIN32 no-shared no-dynamic-engine zlib
call :genfile
call :clndir
popd

pushd dllarm64
perl %OPENSSL_DIR%\Configure --prefix="%ProgramFiles%\OpenSSL-3" --with-zlib-include=%ZLIB_DIR% --with-zlib-lib=%ZLIB_DIR%\build\ARM64\Release\libz-static.lib VC-WIN64-ARM no-dynamic-engine zlib
call :genfile
call :clndir
popd

pushd libarm64
perl %OPENSSL_DIR%\Configure --prefix="%ProgramFiles%\OpenSSL-3" --with-zlib-include=%ZLIB_DIR% --with-zlib-lib=%ZLIB_DIR%\build\ARM64\Release\libz-static.lib VC-WIN64-ARM no-shared no-dynamic-engine zlib
call :genfile
call :clndir
popd

pushd dllarm32
perl %OPENSSL_DIR%\Configure --prefix="%ProgramFiles%\OpenSSL-3" --with-zlib-include=%ZLIB_DIR% --with-zlib-lib=%ZLIB_DIR%\build\ARM\Release\libz-static.lib VC-WIN32-ARM no-dynamic-engine zlib
call :genfile
call :clndir
popd

pushd libarm32
perl %OPENSSL_DIR%\Configure --prefix="%ProgramFiles%\OpenSSL-3" --with-zlib-include=%ZLIB_DIR% --with-zlib-lib=%ZLIB_DIR%\build\ARM\Release\libz-static.lib VC-WIN32-ARM no-shared no-dynamic-engine zlib
call :genfile
call :clndir
popd

goto :end

:genfile
for %%f in ( %_GEN_LIST_INCL% ) do (
  perl -I. -Mconfigdata %OPENSSL_DIR%\util\dofile.pl -omakefile %OPENSSL_DIR%\%%f.in > %%f
)
for %%f in ( %_GEN_LIST_PARAMNAMES_INCL% %_GEN_LIST_PARAMNAMES_CSRC% ) do (
  perl -I. -I%OPENSSL_DIR%\util\perl -Mconfigdata "-MOpenSSL::paramnames" %OPENSSL_DIR%\util\dofile.pl -omakefile %OPENSSL_DIR%\%%f.in > %%f
)
for %%f in ( %_GEN_LIST_PROV_INCL% %_GEN_LIST_PROV_CSRC% ) do (
  perl -I. -I%OPENSSL_DIR%\providers\common\der -Mconfigdata -Moids_to_c %OPENSSL_DIR%\util\dofile.pl -omakefile %OPENSSL_DIR%\%%f.in > %%f
)
perl %OPENSSL_DIR%\apps\progs.pl -C apps\openssl > apps\progs.c
perl %OPENSSL_DIR%\apps\progs.pl -H apps\openssl > apps\progs.h
perl -I. -Mconfigdata %OPENSSL_DIR%\util\dofile.pl -omakefile %OPENSSL_DIR%\apps\CA.pl.in > apps\CA.pl
perl -I. -Mconfigdata %OPENSSL_DIR%\util\dofile.pl -omakefile %OPENSSL_DIR%\apps\tsget.in > apps\tsget.pl
perl -I. -Mconfigdata %OPENSSL_DIR%\util\dofile.pl -omakefile %OPENSSL_DIR%\tools\c_rehash.in > tools\c_rehash.pl
perl -I. -Mconfigdata %OPENSSL_DIR%\util\dofile.pl -omakefile %OPENSSL_DIR%\util\wrap.pl.in > util\wrap.pl
ren configdata.pm configdata.pm.org
@rem Redirection must be at front for "^^" to work. Strange.
>configdata.pm sed -e "s/%OPENSSL_DIR_SED%/\./g" -e "s/\(['\"]\)[A-Za-z]:[^^'\"]*\/%OPENSSL_BASE_SED%\(['\"\/]\)/\1\.\2/" -e "s/\"RANLIB\" =^> \"CODE(0x[0-9a-f]\+)\"/\"RANLIB\" =^> \"CODE(0xf1e2d3c4)\"/" -e "s/\(\"multilib\"\)/#\1/" configdata.pm.org
dos2unix %_GEN_LIST%
exit /b

:clndir
@echo off
call :clndir0
@echo on
exit /b

:clndir0
for /d %%d in ( * ) do (
    pushd %%d
    call :clndir0
    popd
    rmdir %%d 2>nul
)
exit /b

:end
endlocal
