/*
  This file is part of the Arduino NINA firmware.
  Copyright (c) 2018 Arduino SA. All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <errno.h>
#include <string.h>

#include <lwip/netdb.h>
#include <lwip/sockets.h>

#include "esp_partition.h"
#include "WiFi.h"

#include "WiFiClient.h"

class __Guard
{
public:
  __Guard(SemaphoreHandle_t handle)
  {
    _handle = handle;

    xSemaphoreTakeRecursive(_handle, portMAX_DELAY);
  }

  ~__Guard()
  {
    xSemaphoreGiveRecursive(_handle);
  }

private:
  SemaphoreHandle_t _handle;
};

#define synchronized __Guard __guard(_mbedMutex);

WiFiClient::WiFiClient() :
  WiFiClient(-1)
{
}

WiFiClient::WiFiClient(int socket) :
  _socket(socket),
  _peek(-1),
  _connected(false),
  _sslON(false),
  _sni(false)
{
  _mbedMutex = xSemaphoreCreateRecursiveMutex();
}

int WiFiClient::connect(const char* host, uint16_t port)
{
  uint32_t address;

  if (!WiFi.hostByName(host, address)) {
    return 0;
  }

  _sni = true;
  _hostSNI = host;
  return connect(address, port);
}

int WiFiClient::connect(/*IPAddress*/uint32_t ip, uint16_t port)
{
  _sslON = false;
  _socket = lwip_socket(AF_INET, SOCK_STREAM, 0);

  if (_socket < 0) {
    _socket = -1;
    return 0;
  }

  struct sockaddr_in addr;
  memset(&addr, 0x00, sizeof(addr));

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = (uint32_t)ip;
  addr.sin_port = htons(port);

  if (lwip_connect_r(_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    lwip_close_r(_socket);
    _socket = -1;
    return 0;
  }

  int nonBlocking = 1;
  lwip_ioctl_r(_socket, FIONBIO, &nonBlocking);

  return 1;
}

size_t WiFiClient::write(uint8_t b)
{
  return write(&b, 1);
}

size_t WiFiClient::write(const uint8_t *buf, size_t size)
{
  if (_sslON)
  {
    synchronized
    {
      int written = mbedtls_ssl_write(&_sslContext, buf, size);

      if (written < 0)
      {
        written = 0;
      }

      return written;
    }
  }
  else
  {
  if (_socket == -1) {
    return 0;
  }

  int result = lwip_send_r(_socket, (void*)buf, size, MSG_DONTWAIT);

  if (result < 0) {
    lwip_close_r(_socket);
    _socket = -1;
    return 0;
  }

  return result;
  }
}

int WiFiClient::available()
{
  if (_sslON)
  {
    synchronized
    {
      int result = mbedtls_ssl_read(&_sslContext, NULL, 0);

      int n = mbedtls_ssl_get_bytes_avail(&_sslContext);

      if (n == 0 && result != 0 && result != MBEDTLS_ERR_SSL_WANT_READ)
      {
        stop();
      }

      return n;
    }
  }
  else
  {
  if (_socket == -1) {
    return 0;
  }

  int result = 0;

  if (lwip_ioctl_r(_socket, FIONREAD, &result) < 0) {
    lwip_close_r(_socket);
    _socket = -1;
    return 0;
  }

  return result;
  }
}

int WiFiClient::read()
{
  if (_sslON)
  {
    uint8_t b;

    if (_peek != -1)
    {
      b = _peek;
      _peek = -1;
    }
    else if (read(&b, sizeof(b)) == -1)
    {
      return -1;
    }

    return b;
  }
  else
  {
    uint8_t b;

    if (read(&b, sizeof(b)) == -1)
    {
      return -1;
    }
    return b;
  }
}

int WiFiClient::read(uint8_t* buf, size_t size)
{
   if (_sslON)
  {
    synchronized
    {
      if (!available())
      {
        return -1;
      }

      int result = mbedtls_ssl_read(&_sslContext, buf, size);

      if (result < 0)
      {
        if (result != MBEDTLS_ERR_SSL_WANT_READ && result != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
          stop();
        }

        return -1;
      }

      return result;
    }
    //SSL case
  }
  else
  {
  if (!available()) {
    return -1;
  }

  int result = lwip_recv_r(_socket, buf, size, MSG_DONTWAIT);

  if (result <= 0 && errno != EWOULDBLOCK) {
    lwip_close_r(_socket);
    _socket = -1;
    return 0;
  }

  if (result == 0) {
    result = -1;
  }

  return result;
  }
}

int WiFiClient::peek()
{
  if (_sslON)
  {
    if (_peek == -1)
    {
      _peek = read();
    }

    return _peek;
  }
  else
  {
  uint8_t b;

  if (recv(_socket, &b, sizeof(b), MSG_PEEK | MSG_DONTWAIT) <= 0) {
    if (errno != EWOULDBLOCK) {
      lwip_close_r(_socket);
      _socket = -1;
    }

    return -1;
  }

  return b;
  }
}

void WiFiClient::flush()
{
}

void WiFiClient::stop()
{
  if (_sslON)
  {
    synchronized
    {
      if (_socket != -1)
      {
        mbedtls_ssl_session_reset(&_sslContext);

        lwip_close_r(_socket);
        mbedtls_x509_crt_free(&_caCrt);
        mbedtls_entropy_free(&_entropyContext);
        mbedtls_ssl_config_free(&_sslConfig);
        mbedtls_ctr_drbg_free(&_ctrDrbgContext);
        mbedtls_ssl_free(&_sslContext);
      }

      _connected = false;
      _sslON = false;
      _socket = -1;
    }
  }
  else
  {
  if (_socket != -1) {
    lwip_close_r(_socket);
    _socket = -1;
  }
  }
}

uint8_t WiFiClient::connected()
{
  if (_sslON)
  {
    synchronized
    {
      if (!_connected)
      {
        return 0;
      }

      if (available())
      {
        return 1;
      }

      return 1;
    }
  }
  else
  {
  if (_socket != -1) {
    // use peek to update socket state
    peek();
  }

  return (_socket != -1);
  }
}

WiFiClient::operator bool()
{
  if (_sslON)
  {
    return ((_socket != -1) && _connected);
  }
  else
  {
  return (_socket != -1);
  }
}

bool WiFiClient::operator==(const WiFiClient &other) const
{
  return (_socket == other._socket);
}

/*IPAddress*/uint32_t WiFiClient::remoteIP()
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof(addr);

  getpeername(_socket, (struct sockaddr*)&addr, &len);

  return ((struct sockaddr_in *)&addr)->sin_addr.s_addr;
}

uint16_t WiFiClient::remotePort()
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof(addr);

  getpeername(_socket, (struct sockaddr*)&addr, &len);

  return ntohs(((struct sockaddr_in *)&addr)->sin_port);
}

int WiFiClient::handshakeTLS()
{
  _sslON = true;
  synchronized
  {
    _connected = false;

    mbedtls_ssl_init(&_sslContext);
    mbedtls_ctr_drbg_init(&_ctrDrbgContext);
    mbedtls_ssl_config_init(&_sslConfig);
    mbedtls_entropy_init(&_entropyContext);
    mbedtls_x509_crt_init(&_caCrt);

    if (_socket < 0)
    {
      _socket = -1;
      return 0;
    }

    if (mbedtls_ctr_drbg_seed(&_ctrDrbgContext, mbedtls_entropy_func, &_entropyContext, NULL, 0) != 0)
    {
      //stop();
      return 0;
    }

    if (mbedtls_ssl_config_defaults(&_sslConfig, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0)
    {
      //stop();
      return 0;
    }

    mbedtls_ssl_conf_authmode(&_sslConfig, MBEDTLS_SSL_VERIFY_REQUIRED);

    spi_flash_mmap_handle_t handle;
    const unsigned char *certs_data = {};

    const esp_partition_t *part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "certs");
    if (part == NULL)
    {
      return 0;
    }

    int ret = esp_partition_mmap(part, 0, part->size, SPI_FLASH_MMAP_DATA, (const void **)&certs_data, &handle);
    if (ret != ESP_OK)
    {
      return 0;
    }

    ret = mbedtls_x509_crt_parse(&_caCrt, certs_data, strlen((char *)certs_data) + 1);
    if (ret < 0)
    {
      //stop();
      return 0;
    }

    mbedtls_ssl_conf_ca_chain(&_sslConfig, &_caCrt, NULL);

    mbedtls_ssl_conf_rng(&_sslConfig, mbedtls_ctr_drbg_random, &_ctrDrbgContext);

    if (mbedtls_ssl_setup(&_sslContext, &_sslConfig) != 0)
    {
      //stop();
      return 0;
    }
    //sni and host are now variables outside this function
    if (_sni && mbedtls_ssl_set_hostname(&_sslContext, _hostSNI) != 0)
    {
      //stop();
      return 0;
    }

    //connect deleted

    mbedtls_ssl_set_bio(&_sslContext, &_socket, mbedtls_net_send, mbedtls_net_recv, NULL);

    int result;

    do
    {
      result = mbedtls_ssl_handshake(&_sslContext);
    } while (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (result != 0)
    {
      _sslON = false;
      //stop();
      return 0;
    }
    _sslON = true;
    int nonBlocking = 1;
    lwip_ioctl_r(_socket, FIONBIO, &nonBlocking);
    _connected = true;

    return 1;
  }
}