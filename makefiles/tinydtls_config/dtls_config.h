// Not that we'd need *that* code, but if neither ECC nro PSK is defined,
// there's empty unions and such (and newer verisons of the library complain
// more explicitly)
#define DTLS_PSK

// Similarly, without a SHA algorithm, there's unused variables and such
#define WITH_SHA256

// Without, we get a #warning that is escalated to an #error by -Werror
#define HAVE_ASSERT_H
