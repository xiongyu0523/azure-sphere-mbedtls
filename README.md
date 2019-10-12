# Azure Sphere mbedTLS demo

This sample demonstrates mbedTLS based SSL client on Azure Sphere OS (CA7). It downloads a page from www.badiu.com once server side verficiation has passed. 

As of today, Azure Sphere OS does not expose a TLS/SSL API to developer. If a new networking protocol need to be implemented (e.g. MQTT or WebSocket), a TLS/SSL library is always the first middleware should be added to ensure a secure conneciton. With this demo, user can port any application protocol to unlock this limiation. 


To use this sample, clone the repository locally if you haven't already done so:

```
git clone https://github.com/xiongyu0523/azure-sphere-mbedtls.git
```

## mbedTLS port NOTE

1. Offical mbedTLS 2.16.3 release is used. 
   
2. In net_sockets.c, fnctl is commented as Azure Sphere OS does not support this syscall. So `mbedtls_net_set_block` and `mbedtls_net_set_nonblock` are not implemented for user. 

3. In config.h
   
   - `MBEDTLS_FS_IO` is disabled since several FS syscall is not available on Azure Sphere OS
   - `MBEDTLS_NO_PLATFORM_ENTROPY` is enabled, and a pluton based strong entropy is added to poll at application level by `mbedtls_entropy_add_source`
  
        ```
        static int entropy_pluton_source(void* data, unsigned char* output, size_t len, size_t* olen)
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
        ```

4. Beta API is enabled to use `Storage_OpenFileInImagePackage` to retreive CA certificate from imagepackage. 
   
5. DER binary format certifcate is supported, to add more CA certificate, follow this [link](https://docs.microsoft.com/en-us/azure-sphere/app-development/storage#add-a-file-to-an-image-package) to add to project. At application level, call API `mbedtls_x509_crt_parse_der` for several times to add all CA required certificates. 


## To build and run the sample

### Prep your device

1. Ensure that your Azure Sphere device is connected to your PC, and your PC is connected to the internet.
2. Even if you've performed this set up previously, ensure that you have Azure Sphere SDK version 19.09. In an Azure Sphere Developer Command Prompt, run **azsphere show-version** to check. Download and install the [latest SDK](https://aka.ms/AzureSphereSDKDownload) as needed.
3. Open Azure Sphere Developer Command Prompt and issue the following command:

   ```
   azsphere dev prep-debug
   ```


### Build and deploy the application

1. Start Visual Studio.
2. From the **File** menu, select **Open > Open a project or Solution** and navigate to the git folder 
3. Select the file azure-sphere-mbedtls.sln and then click **Open**. 
4. Press **F5** to build and debug the application
5. In **Device Output** window, you will observe below logs:
   
   ```
    . Azure Sphere network is... ok
    . Seeding the random number generator... ok
    . Loading the CA root certificate ... ok (0 skipped)
    . Connecting to tcp/www.baidu.com/443... ok
    . Setting up the SSL/TLS structure... ok
    . Performing the SSL/TLS handshake... ok
    . Verifying peer X.509 certificate... ok
    > Write to server: 18 bytes written

    GET / HTTP/1.0

    < Read from server: 1023 bytes read

    HTTP/1.0 200 OK
    Accept-Ranges: bytes
    Cache-Control: no-cache
    Content-Length: 14722
    Content-Type: text/html
    Date: Thu, 10 Oct 2019 07:53:59 GMT
    Etag: "5d8b1fec-3982"
    Last-Modified: Wed, 25 Sep 2019 08:06:04 GMT
    P3p: CP=" OTI DSP COR IVA OUR IND COM "
    Pragma: no-cache
    Server: BWS/1.1
    Set-Cookie: BAIDUID=FFA44B336A05A46202ED599399F38108:FG=1; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=2147483647; path=/; domain=.baidu.com
    Set-Cookie: BIDUPSID=FFA44B336A05A46202ED599399F38108; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=2147483647; path=/; domain=.baidu.com
    Set-Cookie: PSTM=1570694039; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=2147483647; path=/; domain=.baidu.com
    Vary: Accept-Encoding
    X-Ua-Compatible: IE=Edge,chrome=1

    <!DOCTYPE html><!--STATUS OK-->
    <html>
    <head>
        <meta http-equiv="content-type" content="text/html;charset=utf-8">
    ...
   ```
