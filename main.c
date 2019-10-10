
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>
#include <applibs/log.h>
#include <applibs/networking.h>

#define SERVER_PORT "443"
#define SERVER_NAME "www.baidu.com"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

#define DEBUG_LEVEL 1

#define GlobalSign_Organization_Validation_CA_SHA256_G2												   \
"-----BEGIN CERTIFICATE-----\r\n"                                      \
"MIIEaTCCA1GgAwIBAgILBAAAAAABRE7wQkcwDQYJKoZIhvcNAQELBQAwVzELMAkG\r\n" \
"A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv\r\n" \
"b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xNDAyMjAxMDAw\r\n" \
"MDBaFw0yNDAyMjAxMDAwMDBaMGYxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i\r\n" \
"YWxTaWduIG52LXNhMTwwOgYDVQQDEzNHbG9iYWxTaWduIE9yZ2FuaXphdGlvbiBW\r\n" \
"YWxpZGF0aW9uIENBIC0gU0hBMjU2IC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IB\r\n" \
"DwAwggEKAoIBAQDHDmw/I5N/zHClnSDDDlM/fsBOwphJykfVI+8DNIV0yKMCLkZc\r\n" \
"C33JiJ1Pi/D4nGyMVTXbv/Kz6vvjVudKRtkTIso21ZvBqOOWQ5PyDLzm+ebomchj\r\n" \
"SHh/VzZpGhkdWtHUfcKc1H/hgBKueuqI6lfYygoKOhJJomIZeg0k9zfrtHOSewUj\r\n" \
"mxK1zusp36QUArkBpdSmnENkiN74fv7j9R7l/tyjqORmMdlMJekYuYlZCa7pnRxt\r\n" \
"Nw9KHjUgKOKv1CGLAcRFrW4rY6uSa2EKTSDtc7p8zv4WtdufgPDWi2zZCHlKT3hl\r\n" \
"2pK8vjX5s8T5J4BO/5ZS5gIg4Qdz6V0rvbLxAgMBAAGjggElMIIBITAOBgNVHQ8B\r\n" \
"Af8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUlt5h8b0cFilT\r\n" \
"HMDMfTuDAEDmGnwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0\r\n" \
"dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMDMGA1UdHwQsMCow\r\n" \
"KKAmoCSGImh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5uZXQvcm9vdC5jcmwwPQYIKwYB\r\n" \
"BQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNv\r\n" \
"bS9yb290cjEwHwYDVR0jBBgwFoAUYHtmGkUNl8qJUC99BM00qP/8/UswDQYJKoZI\r\n" \
"hvcNAQELBQADggEBAEYq7l69rgFgNzERhnF0tkZJyBAW/i9iIxerH4f4gu3K3w4s\r\n" \
"32R1juUYcqeMOovJrKV3UPfvnqTgoI8UV6MqX+x+bRDmuo2wCId2Dkyy2VG7EQLy\r\n" \
"XN0cvfNVlg/UBsD84iOKJHDTu/B5GqdhcIOKrwbFINihY9Bsrk8y1658GEV1BSl3\r\n" \
"30JAZGSGvip2CTFvHST0mdCF/vIhCPnG9vHQWe3WVjwIKANnuvD58ZAWR65n5ryA\r\n" \
"SOlCdjSXVWkkDoPWoC209fN5ikkodBpBocLTJIg1MGCUF7ThBCIxPTsvFwayuJ2G\r\n" \
"K1pp74P1S8SqtCr4fKGxhZSM9AyHDPSsQPhZSZg=\r\n"                         \
"-----END CERTIFICATE-----\r\n"

const char user_CA_pem[] = 
	GlobalSign_Organization_Validation_CA_SHA256_G2
	"";
const size_t user_CA_pem_len = sizeof(user_CA_pem);


static void my_debug(void* ctx, int level,
	const char* file, int line,
	const char* str)
{
	((void)level);

	mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE*)ctx);
}

static int entropy_pluton_source(void* data, unsigned char* output,
	size_t len, size_t* olen)
{
	ssize_t bytes_copied;
	((void)data);

	// getrandom is added after 19.05 to levearge pluton's TRNG
	bytes_copied = getrandom(output, len, 0);
	if (bytes_copied >= 0) {
		*olen = bytes_copied;
		return 0;
	} else {
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	}
}

int main(void)
{
	int ret = 1, len;
	int exit_code = MBEDTLS_EXIT_FAILURE;
	mbedtls_net_context server_fd;
	uint32_t flags;
	unsigned char buf[1024];
	const char* pers = "ssl_client1";

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;

#if defined(MBEDTLS_DEBUG_C)
	mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

	/*
	 * 0. Initialize the RNG and the session data
	 */
	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_printf("\n  . Seeding the random number generator...");
	fflush(stdout);

	mbedtls_entropy_init(&entropy);
	mbedtls_entropy_add_source(&entropy, entropy_pluton_source, NULL, MBEDTLS_ENTROPY_MAX_GATHER, MBEDTLS_ENTROPY_SOURCE_STRONG);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char*)pers,
		strlen(pers))) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/*
	 * 0. Initialize certificates
	 */
	mbedtls_printf("  . Loading the CA root certificate ...");
	fflush(stdout);

	ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char*)user_CA_pem, user_CA_pem_len);
	if (ret < 0)
	{
		mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
		goto exit;
	}

	mbedtls_printf(" ok (%d skipped)\n", ret);

	bool isNetworkingReady = false;
	while ((Networking_IsNetworkingReady(&isNetworkingReady) < 0) || !isNetworkingReady);
	Log_Debug("  . Azure Sphere network is ready!!\n");

	/*
	 * 1. Start the connection
	 */
	mbedtls_printf("  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT);
	fflush(stdout);

	if ((ret = mbedtls_net_connect(&server_fd, SERVER_NAME,
		SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/*
	 * 2. Setup stuff
	 */
	mbedtls_printf("  . Setting up the SSL/TLS structure...");
	fflush(stdout);

	if ((ret = mbedtls_ssl_config_defaults(&conf,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/* OPTIONAL is not optimal for security,
	 * but makes interop easier in this simplified example */
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
		goto exit;
	}

	if ((ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME)) != 0)
	{
		mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
		goto exit;
	}

	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	/*
	 * 4. Handshake
	 */
	mbedtls_printf("  . Performing the SSL/TLS handshake...");
	fflush(stdout);

	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
	{
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
			goto exit;
		}
	}

	mbedtls_printf(" ok\n");

	/*
	 * 5. Verify the server certificate
	 */
	mbedtls_printf("  . Verifying peer X.509 certificate...");

	/* In real life, we probably want to bail out when ret != 0 */
	if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
	{
		char vrfy_buf[512];

		mbedtls_printf(" failed\n");

		mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

		mbedtls_printf("%s\n", vrfy_buf);
	}
	else
		mbedtls_printf(" ok\n");

	/*
	 * 3. Write the GET request
	 */
	mbedtls_printf("  > Write to server:");
	fflush(stdout);

	len = sprintf((char*)buf, GET_REQUEST);

	while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0)
	{
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
			goto exit;
		}
	}

	len = ret;
	mbedtls_printf(" %d bytes written\n\n%s", len, (char*)buf);

	/*
	 * 7. Read the HTTP response
	 */
	mbedtls_printf("  < Read from server:");
	fflush(stdout);

	do
	{
		len = sizeof(buf) - 1;
		memset(buf, 0, sizeof(buf));
		ret = mbedtls_ssl_read(&ssl, buf, len);

		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;

		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
			break;

		if (ret < 0)
		{
			mbedtls_printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
			break;
		}

		if (ret == 0)
		{
			mbedtls_printf("\n\nEOF\n\n");
			break;
		}

		len = ret;
		mbedtls_printf(" %d bytes read\n\n%s", len, (char*)buf);
	} while (1);

	mbedtls_ssl_close_notify(&ssl);

	exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#ifdef MBEDTLS_ERROR_C
	if (exit_code != MBEDTLS_EXIT_SUCCESS)
	{
		char error_buf[100];
		mbedtls_strerror(ret, error_buf, 100);
		mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
	}
#endif

	mbedtls_net_free(&server_fd);

	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

#if defined(_WIN32)
	mbedtls_printf("  + Press Enter to exit this program.\n");
	fflush(stdout); getchar();
#endif

	return(exit_code);
}
