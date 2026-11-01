Source: https://github.com/SciresM/hactool
Revision: 1d64a83450e025622f3468c28fc4164dad2c5ef6 (including its bundled mbedTLS).
Licenses: LICENSE and mbedtls/LICENSE.
Local changes: bounded package slices in main.c; explicit private title-key file;
Android-compatible BASEFILE_FAKE sentinel; BKTR output to --romfs; detect output flush failure in nca.c.
The helper is a separate process, not loaded into the game runtime.
No game files or user keys are included.
