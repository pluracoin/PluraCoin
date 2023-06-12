// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright(c) 2014 - 2017 XDN - project developers
// Copyright(c) 2018 The Plura developers
//
// This file is part of Plura.
//
// Plura is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Plura is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Plura.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <system_error>
#include <thread>

#include "System/Dispatcher.h"
#include "System/Event.h"
#include "System/RemoteContext.h"
#include "Logging/ILogger.h"
#include "Logging/LoggerRef.h"
#include "HTTP/httplib.h"


namespace CryptoNote {
class HttpResponse;
class HttpRequest;
}

namespace Common {
class JsonValue;
}

namespace System {
class TcpConnection;
}

namespace CryptoNote {

class JsonRpcServer {
public:
  JsonRpcServer(System::Dispatcher* sys, System::Event* stopEvent, Logging::ILogger& loggerGroup);
  JsonRpcServer(const JsonRpcServer&) = delete;

  ~JsonRpcServer();

  void init(const std::string& chain_file, const std::string& key_file, bool server_ssl_enable = false);
  void setAuth(const std::string& user, const std::string& password);

  void start(const std::string& bindAddress, uint16_t bindPort, uint16_t bindPortSSL);
  void stop();

protected:
  static void makeErrorResponse(const std::error_code& ec, Common::JsonValue& resp);
  static void makeMethodNotFoundResponse(Common::JsonValue& resp);
  static void makeGenericErrorReponse(Common::JsonValue& resp, const char* what, int errorCode = -32001);
  static void fillJsonResponse(const Common::JsonValue& v, Common::JsonValue& resp);
  static void prepareJsonResponse(const Common::JsonValue& req, Common::JsonValue& resp);
  static void makeJsonParsingErrorResponse(Common::JsonValue& resp);

  virtual void processJsonRpcRequest(const Common::JsonValue& req, Common::JsonValue& resp) = 0;

private:
  void processRequest(const httplib::Request& request, httplib::Response& response);

  void listen(const std::string address, const uint16_t port);
  void listen_ssl(const std::string address, const uint16_t port);
  bool authenticate(const httplib::Request& request) const;

  System::Dispatcher* m_dispatcher;
  System::Event* stopEvent;
  Logging::LoggerRef logger;
  httplib::Server* http;
  httplib::SSLServer* https;

  std::list<std::thread> m_workers;

  std::string m_chain_file;
  std::string m_key_file;
  std::string m_credentials;

  bool m_enable_ssl;
};

} //namespace CryptoNote
