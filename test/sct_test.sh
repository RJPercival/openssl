#!/bin/sh

cmd=./sct_test
sctdir="sct-tests"

test_sct () {
	echo $1 "($2)" 1>&2
	logpubkey="$sctdir/ct-server-key-public.pem"
	precert_signing_cert="NULL"

	ca_type="ca"
	case $1 in
		*intermediate*)
			ca_type="intermediate"
			;;
	esac

	issuer_cert="$sctdir/$ca_type-cert.pem"
	case $1 in
		*preca)
			precert_signing_cert="$sctdir/$ca_type-pre-cert.pem"
			;;
	esac

	case $2 in
		embedded)
			cert="$sctdir/$1-cert.pem"
			precert_signing_cert="NULL"
			sct="NULL"
			;;
		cert)
			cert="$sctdir/$1-cert.pem"
			sct="$sctdir/$1-cert.proof"
			;;
		precert)
			cert="$sctdir/$1-pre-cert.pem"
			sct="$sctdir/$1-pre-cert.proof"
			;;
	esac

	$cmd $logpubkey $issuer_cert $cert $2 $sct $precert_signing_cert
	[ $? != $3 ] && exit 1
}

echo "=== VALID SCTs ===" 1>&2
test_sct test cert 0
test_sct test-embedded embedded 0
test_sct test-embedded precert 0
test_sct test-embedded-with-preca embedded 0
test_sct test-embedded-with-preca precert 0
test_sct test-intermediate cert 0
test_sct test-embedded-with-intermediate embedded 0
test_sct test-embedded-with-intermediate precert 0
test_sct test-embedded-with-intermediate-preca embedded 0
test_sct test-embedded-with-intermediate-preca precert 0

echo "=== INVALID SCTs ===" 1>&2
test_sct test-invalid-embedded embedded 100

echo "ALL SCT TESTS SUCCESSFUL" 1>&2
exit 0
