#ifndef ANET_IOS_FFI_H
#define ANET_IOS_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct AnetIosClient AnetIosClient;

typedef void (*AnetIosEventCallback)(void *context, int32_t event_code,
                                     const char *utf8_payload);
typedef void (*AnetIosPacketCallback)(void *context, const uint8_t *packet,
                                      size_t packet_length);

typedef struct AnetIosCallbacks {
    void *context;
    AnetIosEventCallback on_event;
    AnetIosPacketCallback on_packet;
} AnetIosCallbacks;

/* Event codes: client states 0..6, status=100, warning=101, error=102,
 * account=103, and apply-network-settings=1000. */
AnetIosClient *anet_ios_client_new(const uint8_t *config_utf8,
                                   size_t config_length,
                                   AnetIosCallbacks callbacks);
int32_t anet_ios_client_start(AnetIosClient *client);
int32_t anet_ios_client_send_packet(AnetIosClient *client,
                                    const uint8_t *packet,
                                    size_t packet_length);
int32_t anet_ios_client_complete_network_settings(AnetIosClient *client,
                                                   uint64_t request_id,
                                                   bool succeeded);
int32_t anet_ios_client_reconnect(AnetIosClient *client);
int32_t anet_ios_client_stop(AnetIosClient *client);
void anet_ios_client_free(AnetIosClient *client);

/* Valid until the next FFI call on the same thread. Copy it immediately. */
const char *anet_ios_last_error_message(void);

#endif
