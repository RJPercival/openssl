#! /usr/bin/perl

use OpenSSL::Test::Simple;

simple_test("test_sct", "sct_test.sh", "sct");

