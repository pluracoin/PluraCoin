// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
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

#include "JsonRpc.h"
#include "HTTP/httplib.h"
#include "CryptoNoteCore/TransactionPool.h"

namespace CryptoNote {

namespace JsonRpc {

JsonRpcError::JsonRpcError() : code(0) {}

JsonRpcError::JsonRpcError(int c) : code(c) {
  switch (c) {
  case errParseError: message = "Parse error"; break;
  case errInvalidRequest: message = "Invalid request"; break;
  case errMethodNotFound: message = "Method not found"; break;
  case errInvalidParams: message = "Invalid params"; break;
  case errInternalError: message = "Internal error"; break;
  default: message = "Unknown error"; break;
  }
}

JsonRpcError::JsonRpcError(int c, const std::string& msg) : code(c), message(msg) {
}

void invokeJsonRpcCommand(httplib::Client& httpClient, JsonRpcRequest& jsReq, JsonRpcResponse& jsRes, const std::string& user, const std::string& password) {

  if (!user.empty() || !password.empty()) {
    httpClient.set_basic_auth(user.c_str(), password.c_str());
  }

  auto rsp = httpClient.Post("/json_rpc", jsReq.getBody(), "application/json");

  if (!rsp || rsp->status != 200) {
    throw std::runtime_error("JSON-RPC call failed");
  }

  jsRes.parse(rsp->body);

  JsonRpcError err;
  if (jsRes.getError(err)) {
    throw err;
  }
}


}
}
