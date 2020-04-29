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

#ifndef WIFICLIENT_H
#define WIFICLIENT_H

#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>

#include <Arduino.h>
// #include <Client.h>
// #include <IPAddress.h>

class WiFiServer;

class WiFiClient /*: public Client*/ {

public:
  WiFiClient();

  uint8_t status();

  virtual int connect(/*IPAddress*/uint32_t ip, uint16_t port);
  virtual int connect(const char* host, uint16_t port);
  virtual size_t write(uint8_t);
  virtual size_t write(const uint8_t *buf, size_t size);
  virtual int available();
  virtual int read();
  virtual int read(uint8_t *buf, size_t size);
  virtual int peek();
  virtual void flush();
  virtual void stop();
  virtual uint8_t connected();
  virtual operator bool();
  bool operator==(const WiFiClient &other) const;

  virtual /*IPAddress*/uint32_t remoteIP();
  virtual uint16_t remotePort();
  virtual int handshakeTLS();

  // using Print::write;

protected:
  friend class WiFiServer;

  WiFiClient(int socket);

private:
  int _socket;
  int _peek;
  bool _connected;
  bool _sslON;
  bool _sni;

  const char *_hostSNI;
  static const char* ROOT_CAs;
  mbedtls_entropy_context _entropyContext;
  mbedtls_ctr_drbg_context _ctrDrbgContext;
  mbedtls_ssl_context _sslContext;
  mbedtls_ssl_config _sslConfig;
  mbedtls_x509_crt _caCrt;
  
  SemaphoreHandle_t _mbedMutex;
};

#endif // WIFICLIENT_H
