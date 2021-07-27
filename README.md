# File upload demo on Azure RTOS

This project add file upload feature to [Azure IoT Middleware for Azure RTOS](https://github.com/azure-rtos/netxduo/tree/master/addons/azure_iot) and provide a sample code on top of [Azure_RTOS_6.1_STM32L4+-DISCO_IAR_Samples_2020_10_10.zip](https://github.com/azure-rtos/samples/releases/download/v6.1_rel/Azure_RTOS_6.1_STM32L4+-DISCO_IAR_Samples_2020_10_10.zip) package. 

Refer to [IoT hub document](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-devguide-file-upload) to understand IoT Hub file upload feature.

only block call with TX_WAIT_FOREVER option is supported

## Prerequisites

1. [STM32L4+ Discovery Kit IoT node](https://www.st.com/en/evaluation-tools/b-l4s5i-iot01a.html)

2. [IAR EWARM 8.50](https://www.iar.com/ewarm) or later.

## API

Two new API are added to Azure IoT Hub client. User code is responsible for upload file to Azure blob storage by using the sas token and uri retrieved from API.

> only block call with TX_WAIT_FOREVER option is supported

```
/**
 * @brief Retrieve blob SAS token and URI from IoT Hub 
 * @details This routine send file upload request to IoT Hub to retrieve blob sas token and URI.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[in] target_blob Pointer to blob file name.
 * @param[in] target_blob_len Length of blob file name.
 * @param[out] correlation_id Pointer to the buffer to hold correlation id.
 * @param[in] correlation_id_max_len Maximum length of the correlation id buffer.
 * @param[out] host_name Pointer to the buffer to hold host name.
 * @param[in] host_name_max_len Maximum length of the host name buffer (null is not included).
 * @param[out] container Pointer to the buffer to hold container name.
 * @param[in] container_max_len Maximum length of the container name buffer (null is not included).
 * @param[out] blob_name Pointer to the buffer to hold blob name.
 * @param[in] blob_name_max_len Maximum length of the blob name buffer (null is not included).
 * @param[out] sas_token Pointer to the buffer to hold sas token.
 * @param[in] sas_token_max_len Maximum length of the sas token buffer (null is not included).
 * @param[in] wait_option Ticks to wait for API to complete.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if expected response is received and copied.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail due to invalid parameter.
 *   @retval #NX_AZURE_IOT_SDK_CORE_ERROR Fail due to SDK core error.
 *   @retval NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE Fail due to insufficient buffer space.
 */
UINT nx_azure_iot_hub_file_upload_retrieve_sas_uri(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                   UCHAR *target_blob, UINT target_blob_len,
                                                   UCHAR *correlation_id, UINT correlation_id_max_len,
                                                   UCHAR *host_name, UINT host_name_max_len,
                                                   UCHAR *container, UINT container_max_len,
                                                   UCHAR *blob_name, UINT blob_name_max_len,
                                                   UCHAR *sas_token, UINT sas_token_max_len,
                                                   UINT wait_option);

/**
 * @brief Send file upload complete notification to IoT Hub. 
 * @details This routine send file upload complete notificaiton to IoT Hub.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[in] correlation_id Pointer to the buffer to hold correlation id.
 * @param[in] correlation_id_max_len Length of the correlation id buffer.
 * @param[in] is_success Boolean that indicates whether the file was uploaded successfully.
 * @param[in] status_code Status code report to IoT Hub.
 * @param[in] description Pointer to the buffer to hold description.
 * @param[in] description_len Length of the description buffer.
 * @param[in] wait_option Ticks to wait for API to complete.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if notificaiton is complete wihtout error.
 *   @retval #NX_AZURE_IOT_INVALID_PARAMETER Fail due to invalid parameter.
 *   @retval #NX_AZURE_IOT_SDK_CORE_ERROR Fail due to SDK core error.
 *   @retval NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE Fail due to insufficient buffer space.
 */
UINT nx_azure_iot_hub_file_upload_notify_complete(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                  UCHAR *correlation_id, UINT correlation_id_len,
                                                  UINT is_success, 
                                                  UINT status_code, 
                                                  UCHAR *description, UINT description_len,
                                                  UINT wait_option);
```

## Build and run the sample

1. Clone this repository.
   
   ```
   git clone https://github.com/xiongyu0523/azure-rtos-file-upload
   ```

2. The demo support both certificate and symmetric-key based authentication to IoT Hub. DPS is supported and optional. Configure your IoT Hub and DPS service according to your use case. 

3. Refer to this [page](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-configure-file-upload) to configure IoT Hub file upload to blob storage.

4. Open IAR EWARM workspace by double click **azure_rtos.eww**, Select **Options** > **C/C++ Compiler** >
**Preprocessor Configure** to configure your WIFI_SSID and WIFI_PASSWORD.

5. Expand the sample folder to open *sample_config.h* to set the credential according to your IoT Hub and DPS setting. 

    |  Macro | Sample value  | Note |
    |  ----  | ----  | ---- | 
    | HOST_NAME  | myiothub.azure-devices.net | When ENABLE_DPS_SAMPLE is NOT defined |
    | DEVICE_ID  | mydevice | When ENABLE_DPS_SAMPLE is NOT defined |
    | DEVICE_SYMMETRIC_KEY  | OtSNa...sKQBQOKtQ= | When USE_DEVICE_CERTIFICATE is 0 or not defined |
    | ENDPOINT  | global.azure-devices-provisioning.net | When ENABLE_DPS_SAMPLE is defined  |
    | ID_SCOPE  | 0ne00123456 | When ENABLE_DPS_SAMPLE is defined | 
    | REGISTRATION_ID  | mydevice | | 

6. **(Only if USE_DEVICE_CERTIFICATE is enabled)** 
   - Follow this [page](https://github.com/Azure/azure-iot-sdk-c/blob/master/tools/CACertificates/CACertificateOverview.md) to use script in *tool/CACertificates* folder to generate your own root CA, device certificate and private keys. The key configured in this project is 2048 bits RSA.
   - Modify *sample_device_identity.c* to add your own device certificate and private key. (Use OPENSSL to convert PEM to DER format first and use xcc tool in ubuntu to convert to array format)

6. Connect STM32L4+ discovery STLink USB port to PC. 

7. Select **Project** > **Batch build...** to rebuild the all 4 projects within workspace and press **CTRL+D** to start adebug session. Program will stop at **main()** function, press **F5** to go. 

8. Open **view** -> **Terminal I/O** to check log output. Code will start to upload a test.txt file every 5 seconds.

```

Telemetry message send: {"Message ID":47}.
...
Successfully retrieve sas token and uri from IoT Hub
Start file upload to {yourblob}.blob.core.windows.net/{your container}/{device id}/test.txt
Successfully upload file to blob container
Successfully notify IoT Hub for file upload status
Telemetry message send: {"Message ID":51}.
Telemetry message send: {"Message ID":52}.
Telemetry message send: {"Message ID":53}.
...

```

8. Go to Azure Blob stroage contrainer to check result. By default the demo upload a text.txt file and write content *A sample of file upload* into this file.

## Known issue and limitation

1. To use CA signed certificate, you need a IoT Hub enabled public preview feature.  
2. ASC agent is turned off, otherwise there are MQTT error messages generated, or get a hard fault. 