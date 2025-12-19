// Copyright (c) 2025
// SPDX-License-Identifier: Apache-2.0
// Coskun ERGAN <coskunergan@gmail.com>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/dhcpv4_server.h>
#include <zephyr/net/dhcpv4.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/icmp.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_core.h>
#include <string.h>
#include <errno.h>

LOG_MODULE_DECLARE(esp32_wifi, LOG_LEVEL_DBG);

#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"

#define NET_EVENT_WIFI_MASK                                                                    \
	(NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_WIFI_DISCONNECT_RESULT |                        \
	 NET_EVENT_WIFI_AP_ENABLE_RESULT | NET_EVENT_WIFI_AP_DISABLE_RESULT |                      \
	 NET_EVENT_WIFI_AP_STA_CONNECTED | NET_EVENT_WIFI_AP_STA_DISCONNECTED)

static struct wifi_connect_req_params ap_config;
static struct wifi_connect_req_params sta_config;

static struct net_mgmt_event_callback cb;
struct net_if *ap_iface = NULL;
struct net_if *sta_iface = NULL;
static bool connected;

static struct k_work_delayable ip_config_work;

extern uint8_t get_current_ssid_len(void);
extern const uint8_t *get_current_ssid(void);
extern uint8_t get_current_psk_len(void);
extern const uint8_t *get_current_psk(void);

#if CONFIG_NET_DHCPV4_SERVER
static void enable_dhcpv4_server(void)
{
    if(!ap_iface)
    {
        LOG_ERR("AP interface is NULL!");
        return;
    }

    if(!net_if_is_up(ap_iface))
    {
        net_if_up(ap_iface);
        k_sleep(K_MSEC(300));
    }

    struct in_addr ap_ip;
    struct in_addr netmask;
    struct in_addr gateway;

    if(net_addr_pton(AF_INET, CONFIG_WIFI_SAMPLE_AP_IP_ADDRESS, &ap_ip))
    {
        LOG_ERR("Error: Invalid IP address");
        return -EINVAL;
    }    

    if(net_addr_pton(AF_INET, CONFIG_WIFI_SAMPLE_AP_NETMASK, &netmask))
    {
        LOG_ERR("Error: Invalid Netmask");
        return -EINVAL;
    }  

    gateway = ap_ip;

    net_if_ipv4_addr_rm(ap_iface, &ap_ip);
    net_if_ipv4_addr_add(ap_iface, &ap_ip, NET_ADDR_MANUAL, 0);

    net_if_ipv4_set_netmask(ap_iface, &netmask);

    net_if_ipv4_set_gw(ap_iface, &gateway);

    LOG_INF("AP configured → 192.168.4.1/24 | Gateway: 192.168.4.1");

    struct in_addr pool_start = ap_ip;
    pool_start.s4_addr[3] = 100;

    if(net_dhcpv4_server_start(ap_iface, &pool_start) != 0)
    {
        LOG_ERR("DHCP server start failed");
        return;
    }

    LOG_INF("DHCP server STARTED → 192.168.4.100+");
}
#endif

static void ip_config_work_handler(struct k_work *work)
{
    if(!sta_iface)
    {
        LOG_ERR("STA interface is NULL!");
        return;
    }

    net_dhcpv4_stop(sta_iface);    

    struct in_addr sta_ip;
    struct in_addr netmask;    
    struct in_addr gateway;

    if(net_addr_pton(AF_INET, CONFIG_NET_CONFIG_MY_IPV4_ADDR, &sta_ip))
    {
        LOG_ERR("Error: Invalid IP address");
        return -EINVAL;
    }
    if(net_addr_pton(AF_INET, CONFIG_NET_CONFIG_MY_IPV4_NETMASK, &netmask))
    {
        LOG_ERR("Error: Invalid Net Mask");
        return -EINVAL;
    }
    if(net_addr_pton(AF_INET, CONFIG_NET_CONFIG_MY_IPV4_GW, &gateway))
    {
        LOG_ERR("Error: Invalid Gateway");
        return -EINVAL;
    }    

    net_if_ipv4_addr_rm(sta_iface, &sta_ip);

    if(net_if_ipv4_addr_add(sta_iface, &sta_ip, NET_ADDR_MANUAL, 0) == NULL)
    {
        LOG_ERR("[STA-IP] ERROR: Static IP assaiment failure. Interface state: %s (errno: %d)\n",
                net_if_is_up(sta_iface) ? "UP" : "DOWN", errno);
        return;
    }

    net_if_ipv4_set_netmask(sta_iface, &netmask);
    net_if_ipv4_set_gw(sta_iface, &gateway);
    
    LOG_INF("[STA-IP]   IP:      %u.%u.%u.%u\n",
            sta_ip.s4_addr[0], sta_ip.s4_addr[1],
            sta_ip.s4_addr[2], sta_ip.s4_addr[3]);
    LOG_INF("[STA-IP]   Gateway: %u.%u.%u.%u\n",
            gateway.s4_addr[0], gateway.s4_addr[1],
            gateway.s4_addr[2], gateway.s4_addr[3]);

}

static void wifi_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event, struct net_if *iface)
{
    switch(mgmt_event)
    {
        case NET_EVENT_WIFI_CONNECT_RESULT:
        {
            const struct wifi_status *status = (const struct wifi_status *)cb->info;

            if(status->status != 0)
            {
                LOG_ERR("Wifi Connection ERROR: %d\n", status->status);
                connected = false;
                break;
            }
            sta_iface = iface;
            connected = true;
            net_if_up(iface);
            net_dhcpv4_stop(iface);
            k_work_init_delayable(&ip_config_work, ip_config_work_handler);
            k_work_schedule(&ip_config_work, K_MSEC(3000));
            break;
        }

        case NET_EVENT_WIFI_DISCONNECT_RESULT:
        {
            connected = false;

            k_work_cancel_delayable(&ip_config_work);
            net_dhcpv4_stop(iface);
            LOG_INF("Disconnected from %s", get_current_ssid());
            break;
        }
        case NET_EVENT_WIFI_AP_STA_CONNECTED:
        {
            struct wifi_ap_sta_info *sta_info = (struct wifi_ap_sta_info *)cb->info;

            LOG_INF("station: " MACSTR " joined ", sta_info->mac[0], sta_info->mac[1],
                    sta_info->mac[2], sta_info->mac[3], sta_info->mac[4], sta_info->mac[5]);

            break;
        }
        case NET_EVENT_WIFI_AP_STA_DISCONNECTED:
        {
            struct wifi_ap_sta_info *sta_info = (struct wifi_ap_sta_info *)cb->info;

            LOG_INF("station: " MACSTR " leave ", sta_info->mac[0], sta_info->mac[1],
                    sta_info->mac[2], sta_info->mac[3], sta_info->mac[4], sta_info->mac[5]);
            break;
        }
        default:
            break;
    }
}

static int enable_ap_mode(void)
{
    LOG_INF("Turning on AP Mode");
    ap_config.ssid = (const uint8_t *)CONFIG_WIFI_SAMPLE_AP_SSID;
    ap_config.ssid_length = sizeof(CONFIG_WIFI_SAMPLE_AP_SSID) - 1;
    ap_config.psk = (const uint8_t *)CONFIG_WIFI_SAMPLE_AP_PSK;

    if(sizeof(CONFIG_WIFI_SAMPLE_AP_PSK) <= 1)
    {
        ap_config.security = WIFI_SECURITY_TYPE_NONE;
        ap_config.psk_length = 0;
    }
    else
    {
        ap_config.security = WIFI_SECURITY_TYPE_PSK;
        ap_config.psk_length = sizeof(CONFIG_WIFI_SAMPLE_AP_PSK) - 1;
    }

    ap_config.channel = WIFI_CHANNEL_ANY;
    ap_config.band = WIFI_FREQ_BAND_2_4_GHZ;


#if CONFIG_NET_DHCPV4_SERVER
    enable_dhcpv4_server();
#endif

    int ret = net_mgmt(NET_REQUEST_WIFI_AP_ENABLE, ap_iface, &ap_config,
                       sizeof(struct wifi_connect_req_params));
    if(ret)
    {
        LOG_ERR("NET_REQUEST_WIFI_AP_ENABLE failed, err: %d", ret);
    }

    return ret;
}

static int connect_to_wifi(void)
{
    sta_config.ssid = get_current_ssid();
    sta_config.ssid_length = get_current_ssid_len();
    sta_config.psk = get_current_psk();
    sta_config.psk_length = get_current_psk_len();
    sta_config.channel = WIFI_CHANNEL_ANY;
    sta_config.band = WIFI_FREQ_BAND_2_4_GHZ;

    if(sta_config.psk_length > 0)
    {
        sta_config.security = WIFI_SECURITY_TYPE_PSK;
    }
    else
    {
        sta_config.security = WIFI_SECURITY_TYPE_NONE;
    }

    LOG_INF("Connecting to SSID: %s (PSK Len: %d, Security: %s)",
            sta_config.ssid, sta_config.psk_length,
            sta_config.security == WIFI_SECURITY_TYPE_PSK ? "PSK" : "NONE");

    int retries = 3;
    int ret;
    connected = false;
    while(retries--)
    {
        LOG_INF("WiFi connect attempt %d...", 2 - retries);

        ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, sta_iface,
                       &sta_config, sizeof(sta_config));

        if(ret != 0)
        {
            if(ret == -EALREADY)
            {
                LOG_INF("WiFi already connected or connecting");
                connected = true;
                break;
            }
            else
            {
                LOG_ERR("net_mgmt() failed: %d", ret);
                k_sleep(K_MSEC(3000));
                continue;
            }
        }

        int timeout = 30;
        while(timeout-- && !connected)
        {
            k_msleep(500);
        }

        if(connected)
        {
            LOG_INF("WiFi connected!");
            break;
        }

        LOG_WRN("Connection timeout, retrying...");
    }

    if(!connected)
    {
        LOG_ERR("WiFi connection failed!");
        return -EIO;
    }

    return 0;
}

void wifi_connect(void)
{
    k_sleep(K_MSEC(500));

    net_mgmt_init_event_callback(&cb, wifi_event_handler, NET_EVENT_WIFI_MASK);
    net_mgmt_add_event_callback(&cb);

    ap_iface = net_if_get_wifi_sap();
    sta_iface = net_if_get_wifi_sta();

    if(!ap_iface || !sta_iface)
    {
        LOG_ERR("AP and STA interface not found!");
        return;
    }

    LOG_INF("AP Interface: 0x%p, STA Interface: 0x%p",
            (void *)ap_iface, (void *)sta_iface);

    if(enable_ap_mode() != 0)
    {
        LOG_ERR("AP mode activation failed!");
        return;
    }

    if(connect_to_wifi() != 0)
    {
        LOG_ERR("WiFi STA connection failed!");
    }
}