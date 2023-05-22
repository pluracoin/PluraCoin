// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016, The Forknote developers
// Copyright (c) 2016-2018, The Karbowanec developers
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

#include "RpcServer.h"
#include "version.h"

#include <future>
#include <unordered_map>
#include <time.h>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/dll.hpp>

// CryptoNote
#include <crypto/random.h>
#include "BlockchainExplorerData.h"
#include "Common/Base58.h"
#include "Common/DnsTools.h"
#include "Common/Math.h"
#include "Common/FormatTools.h"
#include "Common/StringTools.h"
#include "CryptoNoteCore/TransactionUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/IBlock.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteProtocol/ICryptoNoteProtocolQuery.h"
#include "P2p/ConnectionContext.h"
#include "P2p/NetNode.h"

#include "CoreRpcServerErrorCodes.h"
#include "JsonRpc.h"

#undef ERROR

const uint32_t MAX_NUMBER_OF_BLOCKS_PER_STATS_REQUEST = 10000;
const uint64_t BLOCK_LIST_MAX_COUNT = 1000;

const std::string program_name = boost::dll::program_location().filename().string();

//todo
const std::string index_start =
R"(<!DOCTYPE html><html><head><meta http-equiv='refresh' content='60'/><style>* { font-family: monospace; } .wrap { word-break: break-all; word-wrap: break-word; } table.counter tbody tr td:first-child { text-align: right; }</style></head><body><svg xmlns="http://www.w3.org/2000/svg" xml:space="preserve" version="1.1" style="vertical-align:middle; padding-right: 10px; shape-rendering:geometricPrecision; text-rendering:geometricPrecision; image-rendering:optimizeQuality; fill-rule:evenodd; clip-rule:evenodd" viewBox="0 0 2500000 2500000" xmlns:xlink="http://www.w3.org/1999/xlink" width="64px" height="64px">
<g><circle fill="#0AACFC" cx="1250000" cy="1250000" r="1214062" /><path fill="#FFED00" d="M1251219 1162750c18009,-3203 34019,-10006 48025,-20412 14009,-10407 27215,-28016 39622,-52029l275750 -538290c10803,-18010 24012,-32419 39218,-43625 15210,-10806 33219,-16410 53232,-16410l174893 0 -343384 633144c-15209,26016 -32419,47228 -51628,63635 -19613,16409 -41225,28815 -64838,37221 36822,9604 67638,25213 92854,47225 24812,21610 48425,52025 70437,91247l330578 668363 -192503 0c-38822,0 -70041,-21213 -93653,-63235l-270947 -566303c-14006,-25215 -29216,-43225 -45622,-54034 -16409,-10803 -37222,-17206 -62034,-18809l0 287359 -151281 0 0 -288559 -111263 0 0 703581 -213716 0 0 -1540835 213716 0 0 673166 111263 0 0 -332981 151281 0 0 330581z"/></g></svg>
)" + program_name + R"( core v. )" PROJECT_VERSION_LONG R"( &bull; )";

const std::string index_finish = " </body></html>";
namespace CryptoNote {

namespace {
template <typename T>
static bool print_as_json(const T& obj) {
  std::cout << CryptoNote::storeToJson(obj) << ENDL;
  return true;
}

template <typename Command>
RpcServer::HandlerFunction binMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const httplib::Request& request, httplib::Response& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromBinaryKeyValue(static_cast<typename Command::request&>(req), request.body)) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    response.set_content(storeToBinaryKeyValue(res.data()), "application/octet-stream");
    return result;
  };
}

template <typename Command>
RpcServer::HandlerFunction jsonMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const httplib::Request& request, httplib::Response& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromJson(static_cast<typename Command::request&>(req), request.body)) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    std::string cors_domain = obj->getCorsDomain();
    if (!cors_domain.empty()) {
      response.set_header("Access-Control-Allow-Origin", cors_domain);
      response.set_header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
      response.set_header("Access-Control-Allow-Methods", "POST, GET");
    }
    response.set_content(storeToJson(res.data()), "application/json");
    return result;
  };
}

template <typename Command>
RpcServer::HandlerFunction httpMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const httplib::Request& request, httplib::Response& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromJson(static_cast<typename Command::request&>(req), request.body)) {
      return false;
    }

    bool result = (obj->*handler)(req, res);

    std::string cors_domain = obj->getCorsDomain();
    if (!cors_domain.empty()) {
      response.set_header("Access-Control-Allow-Origin", cors_domain);
      response.set_header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
      response.set_header("Access-Control-Allow-Methods", "POST, GET");
    }
    response.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
    response.set_header("Expires", "0");
    response.status = 200;

    response.set_content(res, "text/html; charset=UTF-8");

    return result;
  };
}

}

std::unordered_map<std::string, RpcServer::RpcHandler<RpcServer::HandlerFunction>> RpcServer::s_handlers = {

  // binary handlers
  { "/getblocks.bin", { binMethod<COMMAND_RPC_GET_BLOCKS_FAST>(&RpcServer::on_get_blocks), true } },
  { "/queryblocks.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS>(&RpcServer::on_query_blocks), true } },
  { "/queryblockslite.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS_LITE>(&RpcServer::on_query_blocks_lite), true } },
  { "/get_o_indexes.bin", { binMethod<COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES>(&RpcServer::on_get_indexes), true } },
  { "/getrandom_outs.bin", { binMethod<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS>(&RpcServer::on_get_random_outs_bin), true } },
  { "/get_pool_changes.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES>(&RpcServer::on_get_pool_changes), true } },
  { "/get_pool_changes_lite.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES_LITE>(&RpcServer::on_get_pool_changes_lite), true } },

  // plain text/html handlers
  { "/", { httpMethod<COMMAND_HTTP>(&RpcServer::on_get_index), true } },
  { "/supply", { httpMethod<COMMAND_HTTP>(&RpcServer::on_get_supply), false } },
  { "/paymentid", { httpMethod<COMMAND_HTTP>(&RpcServer::on_get_payment_id), true } },

  // get json handlers
  { "/getinfo", { jsonMethod<COMMAND_RPC_GET_INFO>(&RpcServer::on_get_info), true } },
  { "/getheight", { jsonMethod<COMMAND_RPC_GET_HEIGHT>(&RpcServer::on_get_height), true } },
  { "/feeaddress", { jsonMethod<COMMAND_RPC_GET_FEE_ADDRESS>(&RpcServer::on_get_fee_address), true } },
  { "/gettransactionspool", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS_POOL_SHORT>(&RpcServer::on_get_transactions_pool_short), true } },
  { "/gettransactionsinpool", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS_POOL>(&RpcServer::on_get_transactions_pool), true } },
  { "/getrawtransactionspool", { jsonMethod<COMMAND_RPC_GET_RAW_TRANSACTIONS_POOL>(&RpcServer::on_get_transactions_pool_raw), true } },

  // post json handlers
  { "/gettransactions", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS>(&RpcServer::on_get_transactions), false } },
  { "/sendrawtransaction", { jsonMethod<COMMAND_RPC_SEND_RAW_TRANSACTION>(&RpcServer::on_send_raw_transaction), false } },
  { "/getblocks", { jsonMethod<COMMAND_RPC_GET_BLOCKS_FAST>(&RpcServer::on_get_blocks), false } },
  { "/queryblocks", { jsonMethod<COMMAND_RPC_QUERY_BLOCKS>(&RpcServer::on_query_blocks), false } },
  { "/queryblockslite", { jsonMethod<COMMAND_RPC_QUERY_BLOCKS_LITE>(&RpcServer::on_query_blocks_lite), false } },
  { "/get_o_indexes", { jsonMethod<COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES>(&RpcServer::on_get_indexes), false } },
  { "/getrandom_outs", { jsonMethod<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_JSON>(&RpcServer::on_get_random_outs_json), false } },
  { "/get_pool_changes", { jsonMethod<COMMAND_RPC_GET_POOL_CHANGES>(&RpcServer::on_get_pool_changes), true } },
  { "/get_pool_changes_lite", { jsonMethod<COMMAND_RPC_GET_POOL_CHANGES_LITE>(&RpcServer::on_get_pool_changes_lite), true } },
  { "/get_block_details_by_height", { jsonMethod<COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT>(&RpcServer::on_get_block_details_by_height), true } },
  { "/get_block_details_by_hash", { jsonMethod<COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH>(&RpcServer::on_get_block_details_by_hash), true } },
  { "/get_blocks_details_by_heights", { jsonMethod<COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS>(&RpcServer::on_get_blocks_details_by_heights), true } },
  { "/get_blocks_details_by_hashes", { jsonMethod<COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES>(&RpcServer::on_get_blocks_details_by_hashes), true } },
  { "/get_blocks_hashes_by_timestamps", { jsonMethod<COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS>(&RpcServer::on_get_blocks_hashes_by_timestamps), true } },
  { "/get_transaction_details_by_hashes", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HASHES>(&RpcServer::on_get_transactions_details_by_hashes), true } },
  { "/get_transaction_details_by_hash", { jsonMethod<COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH>(&RpcServer::on_get_transaction_details_by_hash), true } },
  { "/get_transaction_details_by_heights", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HEIGHTS>(&RpcServer::on_get_transactions_details_by_heights), true } },
  { "/get_raw_transactions_by_heights", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS_WITH_OUTPUT_GLOBAL_INDEXES_BY_HEIGHTS>(&RpcServer::on_get_transactions_with_output_global_indexes_by_heights), true } },
  { "/get_transaction_hashes_by_payment_id", { jsonMethod<COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID>(&RpcServer::on_get_transaction_hashes_by_paymentid), true } },
  
  // disabled in restricted rpc mode
  { "/start_mining", { jsonMethod<COMMAND_RPC_START_MINING>(&RpcServer::on_start_mining), false } },
  { "/stop_mining", { jsonMethod<COMMAND_RPC_STOP_MINING>(&RpcServer::on_stop_mining), false } },
  { "/stop_daemon", { jsonMethod<COMMAND_RPC_STOP_DAEMON>(&RpcServer::on_stop_daemon), true } },
  { "/getconnections", { jsonMethod<COMMAND_RPC_GET_CONNECTIONS>(&RpcServer::on_get_connections), true } },
  { "/getpeers", { jsonMethod<COMMAND_RPC_GET_PEER_LIST>(&RpcServer::on_get_peer_list), true } },


  // json rpc
  { "/json_rpc", { std::bind(&RpcServer::processJsonRpcRequest, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), true } }
};

RpcServer::RpcServer(
  RpcServerConfig& config,
  System::Dispatcher& dispatcher,
  Logging::ILogger& log,
  CryptoNote::Core& core,
  NodeServer& p2p, ICryptoNoteProtocolQuery& protocolQuery
) :
  m_config(config),
  m_dispatcher(dispatcher),
  logger(log, "RpcServer"),
  m_core(core),
  m_p2p(p2p),
  m_protocolQuery(protocolQuery),
  blockchainExplorerDataBuilder(core, protocolQuery),
  m_view_key(NULL_SECRET_KEY),
  m_fee_acc(boost::value_initialized<AccountPublicAddress>()),
  m_restricted_rpc(m_config.isRestricted()),
  m_cors_domain(m_config.getCors()),
  m_fee_address(""),
  m_fee_amount(0)
{
  if (!m_config.getNodeFeeAddress().empty() && m_config.getNodeFeeAmount() != 0) {
    m_fee_address = m_config.getNodeFeeAddress();
    m_fee_amount = m_config.getNodeFeeAmount();
  }

  if (!m_config.getNodeFeeViewKey().empty()) {
    Crypto::Hash private_view_key_hash;
    size_t size;
    if (!Common::fromHex(m_config.getNodeFeeViewKey(), &private_view_key_hash, sizeof(private_view_key_hash), size) || size != sizeof(private_view_key_hash)) {
      throw std::runtime_error("Could not parse private view key");
    }
    m_view_key = *(struct Crypto::SecretKey*)&private_view_key_hash;
  }

  if (!m_config.getContactInfo().empty()) {
    m_contact_info = m_config.getContactInfo();
  }

  http = new httplib::Server();

  https = new httplib::SSLServer(m_config.getChainFile().c_str(), m_config.getKeyFile().c_str());

  http->Get(".*", [this](const httplib::Request& req, httplib::Response& res) {
    processRequest(req, res);
  });

  https->Get(".*", [this](const httplib::Request& req, httplib::Response& res) {
    processRequest(req, res);
  });

  http->Post(".*", [this](const httplib::Request& req, httplib::Response& res) {
    processRequest(req, res);
  });

  https->Post(".*", [this](const httplib::Request& req, httplib::Response& res) {
    processRequest(req, res);
  });
}

RpcServer::~RpcServer() {
  stop();
}

void RpcServer::start() {
  std::string address = m_config.getBindIP();
  if (m_config.isEnabledSSL()) {
    uint16_t ssl_port = m_config.getBindPortSSL(); // make sure to use separate port for SSL server
    logger(Logging::DEBUGGING, Logging::BRIGHT_MAGENTA) << "bind https to port " << ssl_port << ENDL;

    m_workers.emplace_back(std::unique_ptr<System::RemoteContext<void>>(
      new System::RemoteContext<void>(m_dispatcher, std::bind(&RpcServer::listen_ssl, this, address, ssl_port)))
    );
  }

  uint16_t port = m_config.getBindPort();
  logger(Logging::DEBUGGING, Logging::BRIGHT_MAGENTA) << "bind http to port " << port << ENDL;

  m_workers.emplace_back(std::unique_ptr<System::RemoteContext<void>>(
    new System::RemoteContext<void>(m_dispatcher, std::bind(&RpcServer::listen, this, address, port)))
  );
}

void RpcServer::stop() {
  if (m_config.isEnabledSSL()) {
    https->stop();
  }

  http->stop();

  m_workers.clear();
}

void RpcServer::listen(const std::string address, const uint16_t port) {
  if (!http->listen(address.c_str(), port)) {
    logger(Logging::ERROR) << "Could not bind service to " << address << ":" << port
      << "\nIs another service using this address and port?\n";
  }
}

void RpcServer::listen_ssl(const std::string address, const uint16_t port) {
  if (!https->listen(address.c_str(), port)) {
    logger(Logging::ERROR) << "Could not bind service to " << address << ":" << port
      << "\nIs another service using this address and port?\n";
  }
}

size_t RpcServer::getRpcConnectionsCount() {
  return http->connections_count() + https->connections_count();
}

void RpcServer::processRequest(const httplib::Request& request, httplib::Response& response) {
  logger(Logging::TRACE) << "Incoming RPC request to endpoint " << request.path;

  try {
    auto url = request.path;
    auto it = s_handlers.find(url);

    if (it == s_handlers.end()) {

      if (Common::starts_with(url, "/api/")) {

        std::string block_height_method = "/api/block/height/";
        std::string block_hash_method = "/api/block/hash/";
        std::string tx_hash_method = "/api/transaction/";
        std::string payment_id_method = "/api/payment_id/";
        std::string tx_mempool_method = "/api/mempool/";

        if (Common::starts_with(url, block_height_method)) {

          std::string height_str = url.substr(block_height_method.size());
          uint32_t height = Common::integer_cast<uint32_t>(height_str);
          auto it = s_handlers.find("/get_block_details_by_height");
          if (!it->second.allowBusyCore && !isCoreReady()) {
            response.status = 500;
            response.set_content("Core is busy", "text/html");
            return;
          }
          COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::request req;
          req.blockHeight = height;
          COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::response rsp;
          bool r = on_get_block_details_by_height(req, rsp);
          if (r) {
            response.status = 200;
            response.set_content(storeToJson(rsp), "application/json");
          }
          else {
            response.status = 500;
            response.set_content("Internal error", "text/html");
          }
          return;

        }
        else if (Common::starts_with(url, block_hash_method)) {

          std::string hash_str = url.substr(block_hash_method.size());
          auto it = s_handlers.find("/get_block_details_by_hash");
          if (!it->second.allowBusyCore && !isCoreReady()) {
            response.status = 500;
            response.set_content("Core is busy", "text/html");
            return;
          }
          COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::request req;
          req.hash = hash_str;
          COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::response rsp;
          bool r = on_get_block_details_by_hash(req, rsp);
          if (r) {
            response.status = 200;
            response.set_content(storeToJson(rsp), "application/json");
          }
          else {
            response.status = 500;
            response.set_content("Internal error", "text/html");
          }
          return;
        }
        else if (Common::starts_with(url, tx_hash_method)) {
          std::string hash_str = url.substr(tx_hash_method.size());
          auto it = s_handlers.find("/get_transaction_details_by_hash");
          if (!it->second.allowBusyCore && !isCoreReady()) {
            response.status = 500;
            response.set_content("Core is busy", "text/html");
            return;
          }
          COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::request req;
          req.hash = hash_str;
          COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::response rsp;
          bool r = on_get_transaction_details_by_hash(req, rsp);
          if (r) {
            response.status = 200;
            response.set_content(storeToJson(rsp), "application/json");
          }
          else {
            response.status = 500;
            response.set_content("Internal error", "text/html");
          }
          return;
        }
        else if (Common::starts_with(url, payment_id_method)) {

          std::string pid_str = url.substr(payment_id_method.size());
          auto it = s_handlers.find("/get_transaction_hashes_by_payment_id");
          if (!it->second.allowBusyCore && !isCoreReady()) {
            response.status = 500;
            response.set_content("Core is busy", "text/html");
            return;
          }
          COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::request req;
          req.paymentId = pid_str;
          COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::response rsp;
          bool r = on_get_transaction_hashes_by_paymentid(req, rsp);
          if (r) {
            response.status = 200;
            response.set_content(storeToJson(rsp), "application/json");
          }
          else {
            response.status = 500;
            response.set_content("Internal error", "text/html");
          }
          return;

        }
        else if (Common::starts_with(url, tx_mempool_method)) {

          auto it = s_handlers.find("/gettransactionsinpool");
          if (!it->second.allowBusyCore && !isCoreReady())
          {
            response.status = 500;
            response.set_content("Core is busy", "text/html");
            return;
          }

          COMMAND_RPC_GET_TRANSACTIONS_POOL::request req;
          COMMAND_RPC_GET_TRANSACTIONS_POOL::response rsp;
          bool r = on_get_transactions_pool(req, rsp);
          if (r) {
            response.status = 200;
            response.set_content(storeToJson(rsp), "application/json");
          }
          else {
            response.status = 500;
            response.set_content("Internal error", "text/html");
          }
          return;
        }
      }

      if (Common::starts_with(url, "/explorer/")) {

        std::string page_method = "/explorer/height/";
        std::string block_method = "/explorer/block/";
        std::string tx_method = "/explorer/tx/";
        std::string payment_id_method = "/explorer/payment_id/";
        
        if (Common::starts_with(url, block_method)) {
          std::string hash_str = url.substr(block_method.size());
          if (hash_str.size() < 64) {
            // assume it's height
            uint32_t height = static_cast<uint32_t>(std::stoul(hash_str));
            if (m_core.getCurrentBlockchainHeight() <= height) {
              throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
                std::string("To big height: ") + std::to_string(height) +
                ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
            }
            Crypto::Hash block_hash = m_core.getBlockIdByHeight(height);
            hash_str = Common::podToHex(block_hash);
          }

          COMMAND_EXPLORER_GET_BLOCK_DETAILS_BY_HASH::request req;
          req.hash = hash_str;
          COMMAND_EXPLORER_GET_BLOCK_DETAILS_BY_HASH::response rsp;
          bool r = on_get_explorer_block_by_hash(req, rsp);
          if (r) {
            response.status = 200;
            response.set_content(rsp, "text/html");
          }
          else {
            response.status = 500;
            response.set_content("Internal error", "text/html");
          }
          return;
        }

        if (Common::starts_with(url, tx_method)) {
          std::string hash_str = url.substr(tx_method.size());
          
          COMMAND_EXPLORER_GET_TRANSACTION_DETAILS_BY_HASH::request req;
          req.hash = hash_str;
          COMMAND_EXPLORER_GET_TRANSACTION_DETAILS_BY_HASH::response rsp;

          bool r = on_get_explorer_tx_by_hash(req, rsp);
          if (r) {
            response.status = 200;
            response.set_content(rsp, "text/html");
          }
          else {
            response.status = 500;
            response.set_content("Internal error", "text/html");
          }
          return;
        }

        if (Common::starts_with(url, payment_id_method)) {
          std::string payment_id_str = url.substr(payment_id_method.size());

          COMMAND_EXPLORER_GET_TRANSACTIONS_BY_PAYMENT_ID::request req;
          req.payment_id = payment_id_str;
          COMMAND_EXPLORER_GET_TRANSACTIONS_BY_PAYMENT_ID::response rsp;

          bool r = on_get_explorer_txs_by_payment_id(req, rsp);
          if (r) {
            response.status = 200;
            response.set_content(rsp, "text/html");
          }
          else {
            response.status = 404;
            response.set_content("Not found", "text/html");
          }
          return;
        }

        // default is explorer home
        uint32_t height = 0;
        if (Common::starts_with(url, page_method)) {
          std::string height_str = url.substr(page_method.size());
          height = Common::integer_cast<uint32_t>(height_str);
        }

        COMMAND_EXPLORER::request req;
        req.height = height;
        COMMAND_EXPLORER::response rsp;
        bool r = on_get_explorer(req, rsp);
        if (r) {
          response.status = 200;
          response.set_content(rsp, "text/html");
        }
        else {
          response.status = 500;
          response.set_content("Internal error", "text/html");
        }
        return;

      }
      response.status = 404;
      return;
    }
    if (!it->second.allowBusyCore && !isCoreReady()) {
      response.status = 500;
      response.set_content("Core is busy", "text/html");
      return;
    }

    it->second.handler(this, request, response);

  }
  catch (const JsonRpc::JsonRpcError& err) {
    response.status = 500;
    response.set_content(storeToJsonValue(err).toString(), "application/json");
  }
  catch (const std::exception& e) {
    response.status = 500;
    response.set_content(e.what(), "text/html");
  }
}

bool RpcServer::processJsonRpcRequest(const httplib::Request& request, httplib::Response& response) {

  using namespace JsonRpc;

  response.set_header("Content-Type", "application/json");
  if (!m_cors_domain.empty()) {
    response.set_header("Access-Control-Allow-Origin", m_cors_domain);
    response.set_header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    response.set_header("Access-Control-Allow-Methods", "POST, GET");
  }  

  JsonRpcRequest jsonRequest;
  JsonRpcResponse jsonResponse;

  try {
    //logger(Logging::TRACE) << "JSON-RPC request: " << request.getBody();
    jsonRequest.parseRequest(request.body);
    jsonResponse.setId(jsonRequest.getId()); // copy id

    static std::unordered_map<std::string, RpcServer::RpcHandler<JsonMemberMethod>> jsonRpcHandlers = {
  
      { "getblockcount", { makeMemberMethod(&RpcServer::on_getblockcount), true } },
      { "getblockhash", { makeMemberMethod(&RpcServer::on_getblockhash), true } },
      { "getblocktemplate", { makeMemberMethod(&RpcServer::on_getblocktemplate), true } },
      { "getblockheaderbyhash", { makeMemberMethod(&RpcServer::on_get_block_header_by_hash), true } },
      { "getblockheaderbyheight", { makeMemberMethod(&RpcServer::on_get_block_header_by_height), true } },
      { "getblocktimestamp", { makeMemberMethod(&RpcServer::on_get_block_timestamp_by_height), true } },
      { "getblockbyheight", { makeMemberMethod(&RpcServer::on_get_block_details_by_height), true } },
      { "getblockbyhash", { makeMemberMethod(&RpcServer::on_get_block_details_by_hash), true } },
      { "getblocksbyheights", { makeMemberMethod(&RpcServer::on_get_blocks_details_by_heights), true } },
      { "getblocksbyhashes", { makeMemberMethod(&RpcServer::on_get_blocks_details_by_hashes), true } },
      { "getblockshashesbytimestamps", { makeMemberMethod(&RpcServer::on_get_blocks_hashes_by_timestamps), true } },
      { "getblockslist", { makeMemberMethod(&RpcServer::on_blocks_list_json), true } },
      { "getaltblockslist", { makeMemberMethod(&RpcServer::on_alt_blocks_list_json), true } },
      { "getlastblockheader", { makeMemberMethod(&RpcServer::on_get_last_block_header), true } },
      { "gettransaction", { makeMemberMethod(&RpcServer::on_get_transaction_details_by_hash), true } },
      { "gettransactionspool", { makeMemberMethod(&RpcServer::on_get_transactions_pool_short), true } },
      { "getrawtransactionspool", { makeMemberMethod(&RpcServer::on_get_transactions_pool_raw), true } },
      { "gettransactionsinpool", { makeMemberMethod(&RpcServer::on_get_transactions_pool), true } },
      { "gettransactionsbypaymentid", { makeMemberMethod(&RpcServer::on_get_transactions_by_payment_id), true } },
      { "gettransactionhashesbypaymentid", { makeMemberMethod(&RpcServer::on_get_transaction_hashes_by_paymentid), true } },
      { "gettransactionsbyhashes", { makeMemberMethod(&RpcServer::on_get_transactions_details_by_hashes), true } },
      { "gettransactionsbyheights", { makeMemberMethod(&RpcServer::on_get_transactions_details_by_heights), true } },
      { "getrawtransactionsbyheights", { makeMemberMethod(&RpcServer::on_get_transactions_with_output_global_indexes_by_heights), true } },
      { "getcurrencyid", { makeMemberMethod(&RpcServer::on_get_currency_id), true } },
      { "getstatsbyheights", { makeMemberMethod(&RpcServer::on_get_stats_by_heights), false } },
      { "getstatsinrange", { makeMemberMethod(&RpcServer::on_get_stats_by_heights_range), false } },
      { "checktransactionkey", { makeMemberMethod(&RpcServer::on_check_transaction_key), true } },
      { "checktransactionbyviewkey", { makeMemberMethod(&RpcServer::on_check_transaction_with_view_key), true } },
      { "checktransactionproof", { makeMemberMethod(&RpcServer::on_check_transaction_proof), true } },
      { "checkreserveproof", { makeMemberMethod(&RpcServer::on_check_reserve_proof), true } },
      { "checkpayment", { makeMemberMethod(&RpcServer::on_check_payment), true } },
      { "validateaddress", { makeMemberMethod(&RpcServer::on_validate_address), true } },
      { "verifymessage", { makeMemberMethod(&RpcServer::on_verify_message), true } },
      { "submitblock", { makeMemberMethod(&RpcServer::on_submitblock), false } },
      { "resolveopenalias", { makeMemberMethod(&RpcServer::on_resolve_open_alias), true } },
      { "search", { makeMemberMethod(&RpcServer::on_explorer_search), true } },

    };

    auto it = jsonRpcHandlers.find(jsonRequest.getMethod());
    if (it == jsonRpcHandlers.end()) {
      throw JsonRpcError(JsonRpc::errMethodNotFound);
    }

    if (!it->second.allowBusyCore && !isCoreReady()) {
      throw JsonRpcError(CORE_RPC_ERROR_CODE_CORE_BUSY, "Core is busy");
    }

    it->second.handler(this, jsonRequest, jsonResponse);

  } catch (const JsonRpcError& err) {
    jsonResponse.setError(err);
  } catch (const std::exception& e) {
    jsonResponse.setError(JsonRpcError(JsonRpc::errInternalError, e.what()));
  }

  response.set_content(jsonResponse.getBody(), "application/json");
  //logger(Logging::TRACE) << "JSON-RPC response: " << jsonResponse.getBody();
  return true;
}

std::string RpcServer::getCorsDomain() {
  return m_cors_domain;
}

bool RpcServer::isCoreReady() {
  return m_core.currency().isTestnet() || m_p2p.get_payload_object().isSynchronized();
}

bool RpcServer::checkIncomingTransactionForFee(const BinaryArray& tx_blob) {
  Crypto::Hash tx_hash = NULL_HASH;
  Crypto::Hash tx_prefixt_hash = NULL_HASH;
  Transaction tx;
  if (!parseAndValidateTransactionFromBinaryArray(tx_blob, tx, tx_hash, tx_prefixt_hash)) {
    logger(Logging::INFO) << "Could not parse tx from blob";
    return false;
  }

  // always relay fusion transactions
  uint64_t inputs_amount = 0;
  get_inputs_money_amount(tx, inputs_amount);
  uint64_t outputs_amount = get_outs_money_amount(tx);

  const uint64_t fee = inputs_amount - outputs_amount;
  if (fee == 0 && m_core.currency().isFusionTransaction(tx, tx_blob.size(), m_core.getCurrentBlockchainHeight() - 1)) {
    logger(Logging::DEBUGGING) << "Masternode received fusion transaction, relaying with no fee check";
    return true;
  }

  CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);

  std::vector<uint32_t> out;
  uint64_t amount;

  CryptoNote::findOutputsToAccount(transaction, m_fee_acc, m_view_key, out, amount);

  if (amount < m_fee_amount)
    return false;

  logger(Logging::INFO) << "Masternode received relayed transaction fee: " << m_core.currency().formatAmount(amount) << " PLURA";

  return true;
}

//
// Binary handlers
//

bool RpcServer::on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res) {
  // TODO code duplication see InProcessNode::doGetNewBlocks()
  if (req.block_ids.empty()) {
    res.status = "Failed";
    return false;
  }

  if (req.block_ids.back() != m_core.getBlockIdByHeight(0)) {
    res.status = "Failed";
    return false;
  }

  uint32_t totalBlockCount;
  uint32_t startBlockIndex;
  std::vector<Crypto::Hash> supplement = m_core.findBlockchainSupplement(req.block_ids, COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT, totalBlockCount, startBlockIndex);

  res.current_height = totalBlockCount;
  res.start_height = startBlockIndex;

  for (const auto& blockId : supplement) {
    assert(m_core.have_block(blockId));
    auto completeBlock = m_core.getBlock(blockId);
    assert(completeBlock != nullptr);

    res.blocks.resize(res.blocks.size() + 1);
    res.blocks.back().block = Common::asString(toBinaryArray(completeBlock->getBlock()));

    res.blocks.back().txs.reserve(completeBlock->getTransactionCount());
    for (size_t i = 0; i < completeBlock->getTransactionCount(); ++i) {
      res.blocks.back().txs.push_back(Common::asString(toBinaryArray(completeBlock->getTransaction(i))));
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_query_blocks(const COMMAND_RPC_QUERY_BLOCKS::request& req, COMMAND_RPC_QUERY_BLOCKS::response& res) {
  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset;

  if (!m_core.queryBlocks(req.block_ids, req.timestamp, startHeight, currentHeight, fullOffset, res.items)) {
    res.status = "Failed to perform query";
    return false;
  }

  res.start_height = startHeight;
  res.current_height = currentHeight;
  res.full_offset = fullOffset;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_query_blocks_lite(const COMMAND_RPC_QUERY_BLOCKS_LITE::request& req, COMMAND_RPC_QUERY_BLOCKS_LITE::response& res) {
  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset;
  if (!m_core.queryBlocksLite(req.blockIds, req.timestamp, startHeight, currentHeight, fullOffset, res.items)) {
    res.status = "Failed to perform query";
    return false;
  }

  res.startHeight = startHeight;
  res.currentHeight = currentHeight;
  res.fullOffset = fullOffset;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res) {
  std::vector<uint32_t> outputIndexes;
  if (!m_core.get_tx_outputs_gindexs(req.txid, outputIndexes)) {
    res.status = "Failed";
    return true;
  }

  res.o_indexes.assign(outputIndexes.begin(), outputIndexes.end());
  res.status = CORE_RPC_STATUS_OK;
  //logger(Logging::TRACE) << "COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES: [" << res.o_indexes.size() << "]";
  return true;
}

bool RpcServer::on_get_random_outs_bin(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res) {
  res.status = "Failed";
  if (!m_core.get_random_outs_for_amounts(req, res)) {
    return true;
  }

  res.status = CORE_RPC_STATUS_OK;

  return true;
}

bool RpcServer::on_get_random_outs_json(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_JSON::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_JSON::response& res) {
  res.status = "Failed";
  
  COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response bin;

  if (!m_core.get_random_outs_for_amounts(req, bin)) {
    return true;
  }

  res.outs.reserve(bin.outs.size());
  for (size_t i = 0; i < bin.outs.size(); ++i) {
    COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_JSON::outs_for_amount out;
    out.amount = bin.outs[i].amount;
    for (auto& o : bin.outs[i].outs) {
      out.outs.push_back(static_cast<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_JSON::out_entry&>(o));
    }
    res.outs.push_back(out);
  }

  res.status = CORE_RPC_STATUS_OK;

  return true;
}


bool RpcServer::on_get_pool_changes(const COMMAND_RPC_GET_POOL_CHANGES::request& req, COMMAND_RPC_GET_POOL_CHANGES::response& rsp) {
  rsp.status = CORE_RPC_STATUS_OK;
  std::vector<CryptoNote::Transaction> addedTransactions;
  rsp.isTailBlockActual = m_core.getPoolChanges(req.tailBlockId, req.knownTxsIds, addedTransactions, rsp.deletedTxsIds);
  for (auto& tx : addedTransactions) {
    BinaryArray txBlob;
    if (!toBinaryArray(tx, txBlob)) {
      rsp.status = "Internal error";
      break;;
    }

    rsp.addedTxs.emplace_back(std::move(txBlob));
  }
  return true;
}


bool RpcServer::on_get_pool_changes_lite(const COMMAND_RPC_GET_POOL_CHANGES_LITE::request& req, COMMAND_RPC_GET_POOL_CHANGES_LITE::response& rsp) {
  rsp.status = CORE_RPC_STATUS_OK;
  rsp.isTailBlockActual = m_core.getPoolChangesLite(req.tailBlockId, req.knownTxsIds, rsp.addedTxs, rsp.deletedTxsIds);

  return true;
}

bool RpcServer::on_get_blocks_details_by_heights(const COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS::request& req, COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HEIGHTS::response& rsp) {
  try {
    if (req.blockHeights.size() > BLOCK_LIST_MAX_COUNT) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
        std::string("Requested blocks count: ") + std::to_string(req.blockHeights.size()) + " exceeded max limit of " + std::to_string(BLOCK_LIST_MAX_COUNT) };
    }
    std::vector<BlockDetails> blockDetails;
    for (const uint32_t& height : req.blockHeights) {
      if (m_core.getCurrentBlockchainHeight() <= height) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
          std::string("Too big height: ") + std::to_string(height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
      }
      Crypto::Hash block_hash = m_core.getBlockIdByHeight(height);
      Block blk;
      if (!m_core.getBlockByHash(block_hash, blk)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get block by height " + std::to_string(height) + '.' };
      }
      BlockDetails detail;
      if (!blockchainExplorerDataBuilder.fillBlockDetails(blk, detail, false)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill block details." };
      }
      blockDetails.push_back(detail);
    }
    rsp.blocks = std::move(blockDetails);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_blocks_details_by_hashes(const COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES::request& req, COMMAND_RPC_GET_BLOCKS_DETAILS_BY_HASHES::response& rsp) {
  try {
    if (req.blockHashes.size() > BLOCK_LIST_MAX_COUNT) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
        std::string("Requested blocks count: ") + std::to_string(req.blockHashes.size()) + " exceeded max limit of " + std::to_string(BLOCK_LIST_MAX_COUNT) };
    }
    std::vector<BlockDetails> blockDetails;
    for (const Crypto::Hash& hash : req.blockHashes) {
      Block blk;
      if (!m_core.getBlockByHash(hash, blk)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get block by hash " + Common::podToHex(hash) + '.' };
      }
      BlockDetails detail;
      if (!blockchainExplorerDataBuilder.fillBlockDetails(blk, detail, false)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill block details." };
      }
      blockDetails.push_back(detail);
    }
    rsp.blocks = std::move(blockDetails);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_details_by_height(const COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_DETAILS_BY_HEIGHT::response& rsp) {
  try {
    BlockDetails blockDetails;
    if (m_core.getCurrentBlockchainHeight() <= req.blockHeight) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
        std::string("To big height: ") + std::to_string(req.blockHeight) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
    }
    Crypto::Hash block_hash = m_core.getBlockIdByHeight(req.blockHeight);
    Block blk;
    if (!m_core.getBlockByHash(block_hash, blk)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by height " + std::to_string(req.blockHeight) + '.' };
  }
    if (!blockchainExplorerDataBuilder.fillBlockDetails(blk, blockDetails, true)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill block details." };
    }
    rsp.block = blockDetails;
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_details_by_hash(const COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_DETAILS_BY_HASH::response& rsp) {
  try {
    BlockDetails blockDetails;
    Crypto::Hash block_hash;
    if (!parse_hash256(req.hash, block_hash)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "Failed to parse hex representation of block hash. Hex = " + req.hash + '.' };
    }
    Block blk;
    if (!m_core.getBlockByHash(block_hash, blk)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by hash. Hash = " + req.hash + '.' };
    }
    if (!blockchainExplorerDataBuilder.fillBlockDetails(blk, blockDetails, true)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill block details." };
    }
    rsp.block = blockDetails;
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_blocks_hashes_by_timestamps(const COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS::request& req, COMMAND_RPC_GET_BLOCKS_HASHES_BY_TIMESTAMPS::response& rsp) {
  try {
    uint32_t count;
    std::vector<Crypto::Hash> blockHashes;
    if (!m_core.get_blockchain_storage().getBlockIdsByTimestamp(req.timestampBegin, req.timestampEnd, req.limit, blockHashes, count)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get blocks within timestamps " + std::to_string(req.timestampBegin) + " - " + std::to_string(req.timestampEnd) + "." };
    }
    rsp.blockHashes = std::move(blockHashes);
    rsp.count = count;
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_details_by_hashes(const COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HASHES::request& req, COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HASHES::response& rsp) {
  try {
    std::vector<TransactionDetails> transactionsDetails;
    transactionsDetails.reserve(req.transactionHashes.size());

    std::list<Crypto::Hash> missed_txs;
    std::list<Transaction> txs;
    m_core.getTransactions(req.transactionHashes, txs, missed_txs, true);

    if (!txs.empty()) {
      for (const Transaction& tx : txs) {
        TransactionDetails txDetails;
        if (!blockchainExplorerDataBuilder.fillTransactionDetails(tx, txDetails)) {
          throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
            "Internal error: can't fill transaction details." };
        }
        transactionsDetails.push_back(txDetails);
      }

      rsp.transactions = std::move(transactionsDetails);
      rsp.status = CORE_RPC_STATUS_OK;
    }
    if (txs.empty() || !missed_txs.empty()) {
      std::ostringstream ss;
      std::string separator;
      for (const auto& h : missed_txs) {
        ss << separator << Common::podToHex(h);
        separator = ",";
      }
      rsp.status = "transaction(s) not found: " + ss.str() + ".";
    }
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  return true;
}

bool RpcServer::on_get_transaction_details_by_hash(const COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::request& req, COMMAND_RPC_GET_TRANSACTION_DETAILS_BY_HASH::response& rsp) {
  try {
    std::list<Crypto::Hash> missed_txs;
    std::list<Transaction> txs;
    std::vector<Crypto::Hash> hashes;
    Crypto::Hash tx_hash;
    if (!parse_hash256(req.hash, tx_hash)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "Failed to parse hex representation of transaction hash. Hex = " + req.hash + '.' };
    }
    hashes.push_back(tx_hash);
    m_core.getTransactions(hashes, txs, missed_txs, true);

    if (txs.empty() || !missed_txs.empty()) {
      std::string hash_str = Common::podToHex(missed_txs.back());
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "transaction wasn't found. Hash = " + hash_str + '.' };
    }

    TransactionDetails transactionsDetails;
    if (!blockchainExplorerDataBuilder.fillTransactionDetails(txs.back(), transactionsDetails)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't fill transaction details." };
    }

    rsp.transaction = std::move(transactionsDetails);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_details_by_heights(const COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HEIGHTS::request& req, COMMAND_RPC_GET_TRANSACTIONS_DETAILS_BY_HEIGHTS::response& rsp) {
  try {
    if (req.heights.size() > BLOCK_LIST_MAX_COUNT) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
        std::string("Requested blocks count: ") + std::to_string(req.heights.size()) + " exceeded max limit of " + std::to_string(BLOCK_LIST_MAX_COUNT) };
    }

    std::vector<uint32_t> heights;

    if (req.range) {
      if (req.heights.size() != 2) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
          std::string("The range is set to true but heights size is not equal to 2") };
      }
      uint32_t upperBound = std::min(req.heights[1], m_core.getCurrentBlockchainHeight());
      for (uint32_t i = 0; i < (upperBound - req.heights[0]); i++) {
        heights.push_back(req.heights[0] + i);
      }
    }
    else {
      heights = req.heights;
    }

    std::vector<TransactionDetails> transactions;

    for (const uint32_t& height : heights) {
      if (m_core.getCurrentBlockchainHeight() <= height) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
          std::string("To big height: ") + std::to_string(height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
      }

      Crypto::Hash block_hash = m_core.getBlockIdByHeight(height);
      Block blk;
      if (!m_core.getBlockByHash(block_hash, blk)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get block by height " + std::to_string(height) + '.' };
      }

      if (req.include_miner_txs) {
        transactions.reserve(blk.transactionHashes.size() + 1);

        TransactionDetails transactionDetails;
        if (!blockchainExplorerDataBuilder.fillTransactionDetails(blk.baseTransaction, transactionDetails, blk.timestamp)) {
          throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill miner's tx details." };
        }
        transactions.push_back(std::move(transactionDetails));
      }
      else {
        transactions.reserve(blk.transactionHashes.size());
      }

      std::list<Transaction> found;
      std::list<Crypto::Hash> missed;

      if (!blk.transactionHashes.empty()) {
        m_core.getTransactions(blk.transactionHashes, found, missed, false);
        //if (found.size() != blk.transactionHashes.size()) {
        //  throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: not all block's txs were found." };
        //}

        for (const Transaction& tx : found) {
          TransactionDetails transactionDetails;
          if (!blockchainExplorerDataBuilder.fillTransactionDetails(tx, transactionDetails, blk.timestamp)) {
            throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill tx details." };
          }
          if (req.exclude_signatures) {
            transactionDetails.signatures.clear();
          }
          transactions.push_back(std::move(transactionDetails));
        }

        for (const auto& miss_tx : missed) {
          rsp.missed_txs.push_back(Common::podToHex(miss_tx));
        }
      }
    }
    rsp.transactions = std::move(transactions);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_with_output_global_indexes_by_heights(const COMMAND_RPC_GET_TRANSACTIONS_WITH_OUTPUT_GLOBAL_INDEXES_BY_HEIGHTS::request& req, COMMAND_RPC_GET_TRANSACTIONS_WITH_OUTPUT_GLOBAL_INDEXES_BY_HEIGHTS::response& rsp) {
  try {
    std::vector<uint32_t> heights;
    
    if (req.range) {
      if (req.heights.size() != 2) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
          std::string("The range is set to true but heights size is not equal to 2") };
      }
      std::vector<uint32_t> range = req.heights;

      if (range.back() - range.front() > BLOCK_LIST_MAX_COUNT) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
          std::string("Requested blocks count: ") + std::to_string(range.back() - range.front()) + " exceeded max limit of " + std::to_string(BLOCK_LIST_MAX_COUNT) };
      }

      std::sort(range.begin(), range.end());
      uint32_t upperBound = std::min(range[1], m_core.getCurrentBlockchainHeight());
      for (uint32_t i = 0; i < (upperBound - range[0]); i++) {
        heights.push_back(range[0] + i);
      }
    }
    else {
      if (req.heights.size() > BLOCK_LIST_MAX_COUNT) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
          std::string("Requested blocks count: ") + std::to_string(req.heights.size()) + " exceeded max limit of " + std::to_string(BLOCK_LIST_MAX_COUNT) };
      }

      heights = req.heights;
    }

    for (const uint32_t& height : heights) {
      if (m_core.getCurrentBlockchainHeight() <= height) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
          std::string("Too big height: ") + std::to_string(height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
      }

      Crypto::Hash block_hash = m_core.getBlockIdByHeight(height);
      Block blk;
      if (!m_core.getBlockByHash(block_hash, blk)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get block by height " + std::to_string(height) + '.' };
      }

      std::vector<Crypto::Hash> txs_ids;

      if (req.include_miner_txs) {
        txs_ids.reserve(blk.transactionHashes.size() + 1);
        txs_ids.push_back(getObjectHash(blk.baseTransaction));
      }
      else {
        txs_ids.reserve(blk.transactionHashes.size());
      }
      if (!blk.transactionHashes.empty()) {
        txs_ids.insert(txs_ids.end(), blk.transactionHashes.begin(), blk.transactionHashes.end());
      }

      std::vector<Crypto::Hash>::const_iterator ti = txs_ids.begin();

      std::vector<std::pair<Transaction, std::vector<uint32_t>>> txs;
      std::list<Crypto::Hash> missed;

      if (!txs_ids.empty()) {
        if (!m_core.getTransactionsWithOutputGlobalIndexes(txs_ids, missed, txs)) {
          throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error getting transactions with output global indexes" };
        }

        for (const auto &txi : txs) {
          rsp.transactions.push_back(tx_with_output_global_indexes());
          tx_with_output_global_indexes &e = rsp.transactions.back();

          e.hash = *ti++;
          e.block_hash = block_hash;
          e.height = height;
          e.timestamp = blk.timestamp;
          e.transaction = *static_cast<const TransactionPrefix*>(&txi.first);
          e.output_indexes = txi.second;
          e.fee = is_coinbase(txi.first) ? 0 : getInputAmount(txi.first) - getOutputAmount(txi.first);
        }
      }

      for (const auto& miss_tx : missed) {
        rsp.missed_txs.push_back(Common::podToHex(miss_tx));
      }
    }
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}
bool RpcServer::on_get_transaction_hashes_by_paymentid(const COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::request& req, COMMAND_RPC_GET_TRANSACTION_HASHES_BY_PAYMENT_ID::response& rsp) {
  Crypto::Hash pid_hash;
  if (!parse_hash256(req.paymentId, pid_hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of payment id. Hex = " + req.paymentId + '.' };
  }
  try {
    rsp.transactionHashes = m_core.getTransactionHashesByPaymentId(pid_hash);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  rsp.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_check_payment(const COMMAND_RPC_CHECK_PAYMENT_BY_PAYMENT_ID::request& req, COMMAND_RPC_CHECK_PAYMENT_BY_PAYMENT_ID::response& rsp) {
  // get txs with requested payment id
  std::vector<Crypto::Hash> transaction_hashes;
  Crypto::Hash pid_hash;
  if (!parse_hash256(req.payment_id, pid_hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of payment id. Hex = " + req.payment_id + '.' };
  }
  try {
    transaction_hashes = m_core.getTransactionHashesByPaymentId(pid_hash);
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }

  if (transaction_hashes.size() == 0) {
    rsp.status = "not_found";
    return true;
  }

  uint64_t received = 0;

  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.currency().parseAccountAddressString(req.address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.address + '.' };
  }
  // parse view key
  Crypto::Hash view_key_hash;
  size_t size;
  if (!Common::fromHex(req.view_key, &view_key_hash, sizeof(view_key_hash), size) || size != sizeof(view_key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse private view key" };
  }
  Crypto::SecretKey viewKey = *(struct Crypto::SecretKey *) &view_key_hash;

  // fetch tx(s)
  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(transaction_hashes, txs, missed_txs, true);

  if (missed_txs.size() != 0) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Couldn't get transaction with hash: " + Common::podToHex(missed_txs.front()) + '.' };
  }

  for (const auto& tx : txs) {
    // get tx pub key
    Crypto::PublicKey txPubKey = getTransactionPublicKeyFromExtra(tx.extra);

    // obtain key derivation
    Crypto::KeyDerivation derivation;
    if (!Crypto::generate_key_derivation(txPubKey, viewKey, derivation))
    {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to generate key derivation from supplied parameters" };
    }

    // look for outputs
    size_t keyIndex(0);
    std::vector<TransactionOutput> outputs;
    try {
      for (const TransactionOutput& o : tx.outputs) {
        if (o.target.type() == typeid(KeyOutput)) {
          const KeyOutput out_key = boost::get<KeyOutput>(o.target);
          Crypto::PublicKey pubkey;
          derive_public_key(derivation, keyIndex, address.spendPublicKey, pubkey);
          if (pubkey == out_key.key) {
            received += o.amount;

            // count confirmations only for actually paying tx
            // and include only their hashes in responce
            Crypto::Hash blockHash;
            uint32_t blockHeight;
            Crypto::Hash txHash = getObjectHash(tx);
            if (std::find(rsp.transaction_hashes.begin(), rsp.transaction_hashes.end(), txHash) == rsp.transaction_hashes.end()) {
              rsp.transaction_hashes.push_back(txHash);
            }
            if (m_core.getBlockContainingTx(txHash, blockHash, blockHeight)) {
              uint32_t confirmations = m_protocolQuery.getObservedHeight() - blockHeight;
              if  (rsp.confirmations < confirmations) {
                   rsp.confirmations = confirmations;
              }
            }
          }
        }
        ++keyIndex;
      }
    }
    catch (...)
    {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
    }  
  }

  rsp.received_amount = received;

  if (received >= req.amount && rsp.confirmations > 0) {
    rsp.status = "paid";
  }
  else if (received > 0 && received < req.amount) {
    rsp.status = "underpaid";
  }
  else if (rsp.confirmations == 0 && received >= req.amount) {
    rsp.status = "pending";
  }
  else {
    rsp.status = "unpaid";
  }

  return true;
}
//
// HTTP handlers
//

bool RpcServer::on_get_index(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res) {
  const std::time_t uptime = std::time(nullptr) - m_core.getStartTime();
  const std::string uptime_str = std::to_string((unsigned int)floor(uptime / 60.0 / 60.0 / 24.0)) + "d " + std::to_string((unsigned int)floor(fmod((uptime / 60.0 / 60.0), 24.0))) + "h "
    + std::to_string((unsigned int)floor(fmod((uptime / 60.0), 60.0))) + "m " + std::to_string((unsigned int)fmod(uptime, 60.0)) + "s";
  uint32_t top_block_index = m_core.getCurrentBlockchainHeight() - 1;
  uint32_t top_known_block_index = std::max(static_cast<uint32_t>(1), m_protocolQuery.getObservedHeight()) - 1;
  size_t outConn = m_p2p.get_outgoing_connections_count();
  size_t incConn = m_p2p.get_connections_count() - outConn;
  Crypto::Hash last_block_hash = m_core.getBlockIdByHeight(top_block_index);
  size_t white_peerlist_size = m_p2p.getPeerlistManager().get_white_peers_count();
  size_t grey_peerlist_size = m_p2p.getPeerlistManager().get_gray_peers_count();
  size_t alt_blocks_count = m_core.getAlternativeBlocksCount();
  size_t total_tx_count = m_core.getBlockchainTotalTransactions() - top_block_index + 1;
  size_t tx_pool_count = m_core.getPoolTransactionsCount();

  const std::string body = index_start + (m_core.currency().isTestnet() ? "testnet" : "mainnet") +
    "<ul>" +
      "<li>" + "Synchronization status: " + std::to_string(top_block_index) + "/" + std::to_string(top_known_block_index) +
      "<li>" + "Last block hash: " + Common::podToHex(last_block_hash) + "</li>" +
      "<li>" + "Difficulty: " + std::to_string(m_core.getNextBlockDifficulty()) + "</li>" +
      "<li>" + "Alt. blocks: " + std::to_string(alt_blocks_count) + "</li>" +
      "<li>" + "Total transactions in network: " + std::to_string(total_tx_count) + "</li>" +
      "<li>" + "Transactions in pool: " + std::to_string(tx_pool_count) + "</li>" +
      "<li>" + "Connections:" +
        "<ul>" +
          "<li>" + "RPC: " + std::to_string(getRpcConnectionsCount()) + "</li>" +
          "<li>" + "OUT: " + std::to_string(outConn) + "</li>" +
          "<li>" + "INC: " + std::to_string(incConn) + "</li>" +
        "</ul>" +
      "</li>" +
      "<li>" + "Peers: " + std::to_string(white_peerlist_size) + " white, " + std::to_string(grey_peerlist_size) + " grey" + "</li>" +
      "<li>" + "Uptime: " + uptime_str + "</li>" +
    "</ul>" +
    index_finish;

  res = body;

  return true;
}


bool RpcServer::on_get_supply(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res) {
  std::string already_generated_coins = m_core.currency().formatAmount(m_core.getTotalGeneratedAmount());
  res = already_generated_coins;

  return true;
}

bool RpcServer::on_get_payment_id(const COMMAND_HTTP::request& req, COMMAND_HTTP::response& res) {
  Crypto::Hash result;
  Random::randomBytes(32, result.data);
  res = Common::podToHex(result);

  return true;
}

//
// Explorer
//

// TODO !!!

bool RpcServer::on_get_explorer(const COMMAND_EXPLORER::request& req, COMMAND_EXPLORER::response& res) {
  uint32_t top_block_index = m_core.getCurrentBlockchainHeight() - 1;
  std::string body = index_start + (m_core.currency().isTestnet() ? "testnet" : "mainnet") +
    "\n<p>" + "Height: <b>" + std::to_string(top_block_index) + "</b>" +
    " &bull; " + "Difficulty: <b>" + std::to_string(m_core.getNextBlockDifficulty()) + "</b>" +
    " &bull; " + "Alt. blocks: <b>" + std::to_string(m_core.getAlternativeBlocksCount()) + "</b>" +
    " &bull; " + "Transactions: <b>" + std::to_string(m_core.getBlockchainTotalTransactions() - top_block_index + 1) + "</b>" +
    " &bull; " + "Next reward: <b>" + m_core.currency().formatAmount(m_core.currency().calculateReward(m_core.getTotalGeneratedAmount())) + "</b>" +
    "</p>\n";

  const uint32_t print_blocks_count = 10;
  uint32_t req_height = std::max<uint32_t>(req.height == 0 ? top_block_index : req.height, print_blocks_count);
  uint32_t last_height = req_height - print_blocks_count;
  if (last_height < print_blocks_count)
      last_height = 0;

  // Search
  body += R"(
  <form style='padding: 10px;' name='searchform' action='javascript:handleSearch()'>
    <input type='text' name='search' id='txt_search' size='80' placeholder='Search by block height/hash, transaction hash, payment id...'>
    <input type='submit' value='Search'>
  </form>
  <script>
  function handleSearch() {
    var search_str = document.getElementById('txt_search').value;
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/json_rpc', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({
      method: 'search',
      params: {
        query: search_str
      }
    }));
    xhr.onload = function() {
      var data = JSON.parse(this.responseText);
      if (data.result) {
        window.location.href = data.result.result;
      } else if (data.error) {
        alert(data.error.message);
      }
    }
  }
  </script>)";

  // show mempool only on home page
  if (req_height == top_block_index) {
    auto pool = m_core.getMemoryPool();
    if (!pool.empty()) {
      body += "<h2>Transaction pool</h2>";
      body += "<table cellpadding=\"10px\">\n";
      body += "  <thead>\n";
      body += "  <tr>\n";
      body += "    <th>Date</th><th>Hash</th><th>Amount</th><th>Fee</th><th>Size</th>\n";
      body += "  </tr>\n";
      body += "</thead>\n";
      body += "<tbody>\n";
      for (const CryptoNote::tx_memory_pool::TransactionDetails& txd : pool) {
        time_t rawtime = (const time_t)txd.receiveTime;
        struct tm* timeinfo;
        timeinfo = gmtime(&rawtime);
        std::string txHashStr = Common::podToHex(txd.id);

        body += "  <tr>\n";
        body += "    <td>";
        body += asctime(timeinfo);
        body.pop_back(); // remove newline after asctime
        body += "</td>\n    <td>";
        body += "<a class=\"wrap\" href=\"/explorer/tx/" + txHashStr + "\">";
        body += txHashStr;
        body += "</a>";
        body += "</td>\n    <td>";
        body += m_core.currency().formatAmount(getOutputAmount(txd.tx));
        body += "</td>\n    <td>";
        body += m_core.currency().formatAmount(txd.fee);
        body += "</td>\n    <td>";
        body += std::to_string(txd.blobSize);
        body += "</td>\n    <td>";
        body += "  </tr>\n";
      }
      body += "</tbody>\n";
      body += "</table>\n";
    }
  }

  // list last 10 blocks with txs
  body += "<h2>Blocks</h2>";
  body += "<table cellpadding=\"10px\">\n";
  body += "  <thead>\n";
  body += "  <tr>\n";
  body += "    <th>Height</th><th>Date</th><th>Hash</th><th>Size</th><th>Difficulty</th><th>Txs</th>\n";
  body += "  </tr>\n";
  body += "</thead>\n";
  body += "<tbody>\n";

  for (uint32_t i = req_height; i > last_height; i--) {
    Crypto::Hash blockHash = m_core.getBlockIdByHeight(i);
    Block blk;
    if (!m_core.getBlockByHash(blockHash, blk)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by height. Height = " + std::to_string(i) + '.' };
    }

    time_t rawtime = (const time_t)blk.timestamp;
    struct tm* timeinfo;
    timeinfo = gmtime(&rawtime);

    difficulty_type blockDifficulty;
    m_core.getBlockDifficulty(static_cast<uint32_t>(i), blockDifficulty);
    size_t tx_cumulative_block_size;
    m_core.getBlockSize(blockHash, tx_cumulative_block_size);
    size_t blokBlobSize = getObjectBinarySize(blk);
    size_t minerTxBlobSize = getObjectBinarySize(blk.baseTransaction);
    uint64_t blockSize = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
 
    body += "  <tr>\n";
    body += "    <td>";
    body += std::to_string(i);
    body += "</td>\n    <td>";
    body += asctime(timeinfo);
    body.pop_back(); // remove newline after asctime
    body += "</td>\n    <td>";
    body += "<a class=\"wrap\" href=\"/explorer/block/" + Common::podToHex(blockHash) + "\">";
    body += Common::podToHex(blockHash);
    body += "</a>";
    body += "</td>\n    <td>";
    body += std::to_string(blockSize);
    body += "</td>\n    <td>";
    body += std::to_string(blockDifficulty);
    body += "</td>\n    <td>";
    body += std::to_string(blk.transactionHashes.size() + 1);
    body += "</td>\n";
    body += "  </tr>\n";

    if (i == 0)
      break;
  }

  body += "</tbody>\n";
  body += "</table>\n";

  uint32_t curr_page = req_height == 0 ? 0 : (top_block_index - req_height) / print_blocks_count;
  uint32_t total_pages = top_block_index / print_blocks_count;
  uint32_t next_page = req_height - print_blocks_count;
  uint32_t prev_page = std::min<uint32_t>(req_height + print_blocks_count, top_block_index);
  
  body += "<p>";
  if (curr_page != 0) {
    if (prev_page <= top_block_index - print_blocks_count) {
      body += "<a href=\"/explorer/height/";
      body += std::to_string(prev_page);
      body += "\">previous page</a> | ";
    }
    body += "<a href=\"/explorer/\">first page</a> | ";
  }
  body += "current page: ";
  body += std::to_string(curr_page);
  body += " / ";
  body += std::to_string(total_pages);
  if (req_height != 0 && req_height > print_blocks_count) {
    body += " | <a href=\"/explorer/height/";
    body += std::to_string(next_page);
    body += "\">next page</a></p>";
  }

  body += index_finish;

  res = body;

  return true;
}

bool RpcServer::on_explorer_search(const COMMAND_RPC_EXPLORER_SEARCH::request& req, COMMAND_RPC_EXPLORER_SEARCH::response& res) {
  Crypto::Hash hash;

  if (req.query.size() < 64) {
    // assume it's height
    uint32_t height = static_cast<uint32_t>(std::stoul(req.query));
    hash = m_core.getBlockIdByHeight(height);
  } 
  else if (!parse_hash256(req.query, hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse query: " + req.query };
  }

  // check if it's block
  if (m_core.have_block(hash)) {
    res.result = "/explorer/block/" + Common::podToHex(hash);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }

  // check if it's tx
  if (m_core.haveTransaction(hash)) {
    res.result = "/explorer/tx/" + Common::podToHex(hash);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }

  // check if it's payment id
  std::vector<Crypto::Hash> txHashes = m_core.getTransactionHashesByPaymentId(hash);
  if (!txHashes.empty()) {
    res.result = "/explorer/payment_id/" + Common::podToHex(hash);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }

  throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Not found" };
  
  return true;
}

bool RpcServer::on_get_explorer_block_by_hash(const COMMAND_EXPLORER_GET_BLOCK_DETAILS_BY_HASH::request& req, COMMAND_EXPLORER_GET_BLOCK_DETAILS_BY_HASH::response& res) {
  try {
    Crypto::Hash block_hash;
    if (!parse_hash256(req.hash, block_hash)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "Failed to parse hex representation of block hash. Hex = " + req.hash + '.' };
    }
    Block blk;
    if (!m_core.getBlockByHash(block_hash, blk)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by hash. Hash = " + req.hash + '.' };
    }

    Crypto::Hash blockHash = get_block_hash(blk);
    uint32_t blockIndex = boost::get<BaseInput>(blk.baseTransaction.inputs.front()).blockIndex;

    std::string body = index_start + (m_core.currency().isTestnet() ? "testnet" : "mainnet") + "\n<p>";

    body += "<a href=\"/explorer/\">Home</a>";
    body += "<hr />";

    body += "<h2>Block <span class=\"wrap\">" + Common::podToHex(blockHash) + "</span></h2>\n";

    body += "<ul>\n";
    body += "  <li>\n";
    body += "    Index: " + std::to_string(blockIndex) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    time_t rawtime = (const time_t)blk.timestamp;
    struct tm* timeinfo;
    timeinfo = gmtime(&rawtime);
    body += "    Time: " + std::to_string(blk.timestamp) + " &bull; ";
    body += asctime(timeinfo);
    body += "  </li>\n";
    body += "  <li>\n";
    body += "    	Version: " + std::to_string(blk.majorVersion) + "." + std::to_string(blk.minorVersion) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    Crypto::Hash tmpHash = m_core.getBlockIdByHeight(blockIndex);
    bool isOrphaned = blockHash != tmpHash;
    body += "    	Orphan: ";
    if (isOrphaned)
      body += "YES\n";
    else
      body += "NO\n";
    body += "  </li>\n";
    body += "  <li>\n";
    size_t tx_cumulative_block_size;
    m_core.getBlockSize(blockHash, tx_cumulative_block_size);
    size_t blokBlobSize = getObjectBinarySize(blk);
    size_t minerTxBlobSize = getObjectBinarySize(blk.baseTransaction);
    size_t blockSize = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
    body += "    	Size: " + std::to_string(blockSize) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    uint64_t blockDifficulty = 0;
    if (!m_core.getBlockDifficulty(blockIndex, blockDifficulty)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't calcualate difficulty for block " + req.hash + '.' };
    }
    body += "    Difficulty: " + std::to_string(blockDifficulty) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    body += "    Previous block: ";
    body += "<a class=\"wrap\" href=\"/explorer/block/" + Common::podToHex(blk.previousBlockHash) + "\">";
    body += Common::podToHex(blk.previousBlockHash);
    body += "</a>\n";
    body += "  </li>\n";
    if (blk.majorVersion >= BLOCK_MAJOR_VERSION_5) {
      body += "  <li>\n";
      body += "    Miner signature: <span class=\"wrap\">" + Common::podToHex(blk.signature) + "</span>";
      body += "  </li>\n";
    }
    body += "</ul>";

    body += "<h3>Transactions</h3>\n";

    // simple list of tx hashes without details, add coinbase first
    body += "<ol>\n";
    body += "  <li>\n";
    Crypto::Hash coinbaseHash = getObjectHash(blk.baseTransaction);
    std::string txHashStr = Common::podToHex(coinbaseHash);
    body += "    <a class=\"wrap\" href=\"/explorer/tx/" + txHashStr + "\">";
    body += txHashStr;
    body += "</a>";
    body += "  </li>\n";

    for (const auto& t : blk.transactionHashes) {
      body += "  <li>\n";
      body += "    <a class=\"wrap\" href=\"/explorer/tx/" + Common::podToHex(t) + "\">";
      body += Common::podToHex(t);
      body += "    </a>";
      body += "  </li>\n";
    }

    body += "</ol>\n";

    body += index_finish;

    res = body;
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }

  return true;
}

bool RpcServer::on_get_explorer_tx_by_hash(const COMMAND_EXPLORER_GET_TRANSACTION_DETAILS_BY_HASH::request& req, COMMAND_EXPLORER_GET_TRANSACTION_DETAILS_BY_HASH::response& res) {
  try {
    std::list<Crypto::Hash> missed_txs;
    std::list<Transaction> txs;
    std::vector<Crypto::Hash> hashes;
    Crypto::Hash tx_hash;
    if (!parse_hash256(req.hash, tx_hash)) {
      throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "Failed to parse hex representation of transaction hash. Hex = " + req.hash + '.' };
    }
    hashes.push_back(tx_hash);
    m_core.getTransactions(hashes, txs, missed_txs, true);

    if (txs.empty() || !missed_txs.empty()) {
      std::string hash_str = Common::podToHex(missed_txs.back());
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "transaction wasn't found. Hash = " + hash_str + '.' };
    }

    TransactionDetails transactionsDetails;
    if (!blockchainExplorerDataBuilder.fillTransactionDetails(txs.back(), transactionsDetails)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't fill transaction details." };
    }

    std::string body = index_start + (m_core.currency().isTestnet() ? "testnet" : "mainnet") + "\n<p>";

    body += "<a href=\"/explorer/\">Home</a>";
    body += "<hr />";

    body += "<h2>Transaction <span class=\"wrap\">" + Common::podToHex(transactionsDetails.hash) + "</span></h2>\n";

    body += "<ul>\n";
    if (transactionsDetails.inBlockchain) {
      body += "  <li>\n";
      body += "    In block: ";
      body += "<a class=\"wrap\" href=\"/explorer/block/" + Common::podToHex(transactionsDetails.blockHash) + "\">";
      body += std::to_string(transactionsDetails.blockHeight) + " (" + Common::podToHex(transactionsDetails.blockHash) + ")";
      body += "    </a>\n";
      body += "  </li>\n";
      body += "  <li>\n";
      time_t rawtime = (const time_t)transactionsDetails.timestamp;
      struct tm* timeinfo;
      timeinfo = gmtime(&rawtime);
      body += "    First confirmation time: ";
      body += asctime(timeinfo);
      body += "  </li>\n";
    }
    else {
      body += "  <li>\n";
      body += "    Unconfirmed\n";
      body += "  </li>\n";
    }
    body += "  <li>\n";
    body += "    Sum of outputs: " + m_core.currency().formatAmount(transactionsDetails.totalOutputsAmount) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    body += "    Size: " + std::to_string(transactionsDetails.size) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    body += "    Unlock time: " + std::to_string(transactionsDetails.unlockTime) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    body += "    Version: " + std::to_string(transactionsDetails.version) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    body += "    Mixin count: " + std::to_string(transactionsDetails.mixin) + "\n";
    body += "  </li>\n";
    body += "  <li>\n";
    body += "    Public key: <span class=\"wrap\">" + Common::podToHex(transactionsDetails.extra.publicKey) + "</span>\n";
    body += "  </li>\n";
    if (transactionsDetails.hasPaymentId) {
      body += "  <li>\n";
      body += "    Payment ID: <span class=\"wrap\">" + Common::podToHex(transactionsDetails.paymentId) + "</span>\n";
      body += "  </li>\n";
    }
    body += "</ul>\n";

    body += "<h3>Inputs</h3>\n";

    body += "<table class=\"counter\" cellpadding=\"10px\">\n";
    body += "  <thead>\n";
    body += "  <tr>\n";
    body += "    <th>No</th><th>Amount</th><th>Key image</th><th>Output indexes (references)</th>\n";
    body += "  </tr>\n";
    body += "</thead>\n";
    body += "<tbody>\n";
    for (size_t i = 0; i < transactionsDetails.inputs.size(); ++i) {
      const auto& in = transactionsDetails.inputs[i];
      body += "  <tr>\n";
      body += "    <td>" + std::to_string(i) + ")</td>";
      body += "    <td>";
      if (in.type() == typeid(BaseInputDetails)) {
        BaseInputDetails c = boost::get<BaseInputDetails>(in);
        body += m_core.currency().formatAmount(c.amount);
        body += "</td>\n    <td colspan=\"2\">coinbase</td>\n";
      }
      else if (in.type() == typeid(KeyInputDetails)) {
        KeyInputDetails k = boost::get<KeyInputDetails>(in);
        body += m_core.currency().formatAmount(k.input.amount);
        body += "</td>\n    <td class=\"wrap\">";
        body += Common::podToHex(k.input.keyImage);
        body += "</td>\n    <td>";
        for (size_t i = 0; i < k.input.outputIndexes.size(); ++i) {
          body += "    <a href=\"/explorer/tx/" + Common::podToHex(k.outputs[i].transactionHash) + "\">";
          body += std::to_string(k.input.outputIndexes[i]); // key_offset
          body += " (output No " + std::to_string(k.outputs[i].number) +")</a>"; // tx output reference
          body += ", ";
        }
        body.pop_back();
        body.pop_back();
        body += "    </td>\n";
      }
      else if (in.type() == typeid(MultisignatureInputDetails)) {
        MultisignatureInputDetails m = boost::get<MultisignatureInputDetails>(in);
        body += m_core.currency().formatAmount(m.input.amount);
        body += "</td>\n    <td>multisig</td>\n    ";
        body += "output index: " + std::to_string(m.input.outputIndex) + ", ";
        body += "signature count: " + std::to_string(m.input.signatureCount) + ", ";
        body += "output number: " + std::to_string(m.output.number) + ", ";
        body += "output tx hash: <span class=\"wrap\">" + Common::podToHex(m.output.transactionHash) + "</span>";
        body += "    </td>\n";
      }
      body += "  </tr>\n";
    }
    body += "</tbody>\n";
    body += "</table>\n";

    body += "<h3>Outputs</h3>\n";

    body += "<table class=\"counter\" cellpadding=\"10px\">\n";
    body += "  <thead>\n";
    body += "  <tr>\n";
    body += "    <th>No</th><th>Amount</th><th>Public key (stealth address)</th><th>Global index</th>\n";
    body += "  </tr>\n";
    body += "</thead>\n";
    body += "<tbody>\n";
    for (size_t i = 0; i < transactionsDetails.outputs.size(); ++i) {
      const auto& o = transactionsDetails.outputs[i];
      body += "  <tr>\n";
      body += "    <td>" + std::to_string(i) + ")</td>";
      body += "    <td>";
      body += m_core.currency().formatAmount(o.output.amount);
      body += "</td>\n    <td class=\"wrap\">";
      if (o.output.target.type() == typeid(KeyOutput)) {
        KeyOutput ko = boost::get<KeyOutput>(o.output.target);
        body += Common::podToHex(ko);
      }
      else if (o.output.target.type() == typeid(MultisignatureOutput)) {
        body += "multisig\n";
        MultisignatureOutput mo = boost::get<MultisignatureOutput>(o.output.target);
        body += "keys: \n";
        for (const auto& k : mo.keys) {
          body += Common::podToHex(k) + "\n";
        }
        body += "required signature count: ";
        body += std::to_string(mo.requiredSignatureCount);
      }
      body += "</td>\n    <td>";
      body += std::to_string(o.globalIndex);
      body += "    </td>\n";
      body += "  </tr>\n";
    }
    body += "</tbody>\n";
    body += "</table>\n";

    // no signatures e.g. in coinbase
    if (!transactionsDetails.signatures.empty()) {
      body += "<h3>Signatures</h3>\n";

      body += "<ol>\n";
      for (const auto& s0 : transactionsDetails.signatures) {
        body += "  <li>\n";
        body += "    <ol>\n";
        for (const auto& s1 : s0) {
          body += "      <li class=\"wrap\">\n";
          body += "    " + Common::podToHex(s1) + "\n";
          body += "      </li>\n";
        }
        body += "    </ol>\n";
        body += "  </li>\n";
      }
      body += "</ol>\n";
    }
    
    body += index_finish;

    res = body;
  }
  catch (std::system_error& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, e.what() };
    return false;
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }

  return true;
}

bool RpcServer::on_get_explorer_txs_by_payment_id(const COMMAND_EXPLORER_GET_TRANSACTIONS_BY_PAYMENT_ID::request& req, COMMAND_EXPLORER_GET_TRANSACTIONS_BY_PAYMENT_ID::response& res) {
  Crypto::Hash paymentId;
  if (!parse_hash256(req.payment_id, paymentId)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse Payment ID: " + req.payment_id + '.' };
  }

  std::vector<Crypto::Hash> txHashes = m_core.getTransactionHashesByPaymentId(paymentId);

  if (txHashes.empty())
    return false;

  std::string body = index_start + (m_core.currency().isTestnet() ? "testnet" : "mainnet") + "\n<p>";

  body += "<a href=\"/explorer/\">Home</a>";
  body += "<hr />";

  body += "<h2>Payment ID <span class=\"wrap\">" + Common::podToHex(paymentId) + "</span></h2>\n";

  body += "<h3>Transactions with this Payment ID:</h3>\n";

  // simple list of tx hashes without details
  body += "<ol>\n";
  for (const auto& tx : txHashes) {
    std::string txHashStr = Common::podToHex(tx);
    body += "  <li>\n";
    body += "    <a class=\"wrap\" href=\"/explorer/tx/" + txHashStr + "\">";
    body += txHashStr;
    body += "    </a>";
    body += "  </li>\n";
  }
  body += "</ol>\n";

  body += index_finish;

  res = body;

  return true;
}

//
// JSON handlers
//

bool RpcServer::on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res) {
  res.height = m_core.getCurrentBlockchainHeight();
  res.difficulty = m_core.getNextBlockDifficulty();
  res.transactions_count = m_core.getBlockchainTotalTransactions() - res.height; //without coinbase
  res.transactions_pool_size = m_core.getPoolTransactionsCount();
  res.alt_blocks_count = m_core.getAlternativeBlocksCount();
  uint64_t total_conn = m_p2p.get_connections_count();
  res.outgoing_connections_count = m_p2p.get_outgoing_connections_count();
  res.incoming_connections_count = total_conn - res.outgoing_connections_count;
  res.rpc_connections_count = getRpcConnectionsCount();
  res.white_peerlist_size = m_p2p.getPeerlistManager().get_white_peers_count();
  res.grey_peerlist_size = m_p2p.getPeerlistManager().get_gray_peers_count();
  res.last_known_block_index = std::max(static_cast<uint32_t>(1), m_protocolQuery.getObservedHeight()) - 1;
  Crypto::Hash last_block_hash = m_core.getBlockIdByHeight(res.height - 1);
  res.top_block_hash = Common::podToHex(last_block_hash);
  res.version = PROJECT_VERSION_LONG;
  res.contact = m_contact_info.empty() ? std::string() : m_contact_info;
  res.min_fee = m_core.getMinimalFee();
  res.start_time = (uint64_t)m_core.getStartTime();
  uint64_t alreadyGeneratedCoins = m_core.getTotalGeneratedAmount();
  // that large uint64_t number is unsafe in JavaScript environment and therefore as a JSON value so we display it as a formatted string
  res.already_generated_coins = m_core.currency().formatAmount(alreadyGeneratedCoins);
  res.block_major_version = m_core.getCurrentBlockMajorVersion();
  uint64_t nextReward = m_core.currency().calculateReward(alreadyGeneratedCoins);
  res.next_reward = nextReward;
  if (!m_core.getBlockCumulativeDifficulty(res.height - 1, res.cumulative_difficulty)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get last cumulative difficulty." };
  }
  res.max_cumulative_block_size = (uint64_t)m_core.currency().maxBlockCumulativeSize(res.height);

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_stats_by_heights(const COMMAND_RPC_GET_STATS_BY_HEIGHTS::request& req, COMMAND_RPC_GET_STATS_BY_HEIGHTS::response& res) {
  if (m_restricted_rpc)
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_RESTRICTED, std::string("Method disabled") };

  std::chrono::steady_clock::time_point timePoint = std::chrono::steady_clock::now();

  std::vector<block_stats_entry> stats;
  for (const uint32_t& height : req.heights) {
    if (m_core.getCurrentBlockchainHeight() <= height) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
        std::string("To big height: ") + std::to_string(height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight() - 1) };
    }

    block_stats_entry entry;
    entry.height = height;
    if (!m_core.getblockEntry(height, entry.block_size, entry.difficulty, entry.already_generated_coins, entry.reward, entry.transactions_count, entry.timestamp)) {
      throw JsonRpc::JsonRpcError{
            CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get stats for height" + std::to_string(height) };
    }
    stats.push_back(entry);
  }
  res.stats = std::move(stats);
  std::chrono::duration<double> duration = std::chrono::steady_clock::now() - timePoint;
  res.duration = duration.count();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_stats_by_heights_range(const COMMAND_RPC_GET_STATS_BY_HEIGHTS_RANGE::request& req, COMMAND_RPC_GET_STATS_BY_HEIGHTS_RANGE::response& res) {
  std::chrono::steady_clock::time_point timePoint = std::chrono::steady_clock::now();

  uint32_t min = std::max<uint32_t>(req.start_height, 1);
  uint32_t max = std::min<uint32_t>(req.end_height, m_core.getCurrentBlockchainHeight() - 1);
  if (min >= max) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong start and end heights" };
  }

  std::vector<block_stats_entry> stats;

  if (m_restricted_rpc) {
    uint32_t count = std::min<uint32_t>(std::min<uint32_t>(MAX_NUMBER_OF_BLOCKS_PER_STATS_REQUEST, max - min), m_core.getCurrentBlockchainHeight() - 1);
    std::vector<uint32_t> selected_heights(count);
    double delta = (max - min) / static_cast<double>(count - 1);
    std::vector<uint32_t>::iterator i;
    double val;
    for (i = selected_heights.begin(), val = min; i != selected_heights.end(); ++i, val += delta) {
      *i = static_cast<uint32_t>(val);
    }

    for (const uint32_t& height : selected_heights) {
      block_stats_entry entry;
      entry.height = height;
      if (!m_core.getblockEntry(height, entry.block_size, entry.difficulty, entry.already_generated_coins, entry.reward, entry.transactions_count, entry.timestamp)) {
        throw JsonRpc::JsonRpcError{
              CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get stats for height" + std::to_string(height) };
      }
      stats.push_back(entry);
    }
  } else {
    for (uint32_t height = min; height <= max; height++) {
      block_stats_entry entry;
      entry.height = height;
      if (!m_core.getblockEntry(height, entry.block_size, entry.difficulty, entry.already_generated_coins, entry.reward, entry.transactions_count, entry.timestamp)) {
        throw JsonRpc::JsonRpcError{
              CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get stats for height" + std::to_string(height) };
      }
      stats.push_back(entry);
    }
  }

  res.stats = std::move(stats);

  std::chrono::duration<double> duration = std::chrono::steady_clock::now() - timePoint;
  res.duration = duration.count();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_height(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res) {
  res.height = m_core.getCurrentBlockchainHeight();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res) {
  std::vector<Crypto::Hash> vh;
  for (const auto& tx_hex_str : req.txs_hashes) {
    BinaryArray b;
    if (!Common::fromHex(tx_hex_str, b))
    {
      res.status = "Failed to parse hex representation of transaction hash";
      return true;
    }
    if (b.size() != sizeof(Crypto::Hash))
    {
      res.status = "Failed, size of data mismatch";
    }
    vh.push_back(*reinterpret_cast<const Crypto::Hash*>(b.data()));
  }
  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(vh, txs, missed_txs);

  for (auto& tx : txs) {
    res.txs_as_hex.push_back(Common::toHex(toBinaryArray(tx)));
  }

  for (const auto& miss_tx : missed_txs) {
    res.missed_txs.push_back(Common::podToHex(miss_tx));
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_send_raw_transaction(const COMMAND_RPC_SEND_RAW_TRANSACTION::request& req, COMMAND_RPC_SEND_RAW_TRANSACTION::response& res) {
  BinaryArray tx_blob;
  if (!Common::fromHex(req.tx_as_hex, tx_blob))
  {
    logger(Logging::INFO) << "[on_send_raw_tx]: Failed to parse transaction from hexbuff: " << req.tx_as_hex;
    res.status = "Failed";
    return true;
  }

  Crypto::Hash transactionHash = Crypto::cn_fast_hash(tx_blob.data(), tx_blob.size());
  logger(Logging::DEBUGGING) << "transaction " << transactionHash << " came in on_send_raw_tx";

  tx_verification_context tvc = boost::value_initialized<tx_verification_context>();
  if (!m_core.handle_incoming_tx(tx_blob, tvc, false))
  {
    logger(Logging::INFO) << "[on_send_raw_tx]: Failed to process tx";
    res.status = "Failed";
    return true;
  }

  if (tvc.m_verification_failed)
  {
    logger(Logging::INFO) << "[on_send_raw_tx]: transaction verification failed";
    res.status = "Failed";
    return true;
  }

  if (!tvc.m_should_be_relayed)
  {
    logger(Logging::INFO) << "[on_send_raw_tx]: transaction accepted, but not relayed";
    res.status = "Not relayed";
    return true;
  }

  if (!m_fee_address.empty() && m_view_key != NULL_SECRET_KEY) {
    if (!checkIncomingTransactionForFee(tx_blob)) {
      logger(Logging::INFO) << "Transaction not relayed due to lack of node fee";
      res.status = "Not relayed due to lack of node fee";
      return true;
    }
  }

  try {
    NOTIFY_NEW_TRANSACTIONS::request r;
    r.stem = true;
    r.txs.push_back(Common::asString(tx_blob));
    m_core.get_protocol()->relay_transactions(r);
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Error: " + std::string(e.what()) };
    return false;
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_start_mining(const COMMAND_RPC_START_MINING::request& req, COMMAND_RPC_START_MINING::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }
  
  AccountKeys keys = boost::value_initialized<AccountKeys>();

  Crypto::Hash key_hash;
  size_t size;
  if (!Common::fromHex(req.miner_spend_key, &key_hash, sizeof(key_hash), size) || size != sizeof(key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse miner spend key" };
  }
  keys.spendSecretKey = *(struct Crypto::SecretKey *) &key_hash;

  if (!Common::fromHex(req.miner_view_key, &key_hash, sizeof(key_hash), size) || size != sizeof(key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse miner view key" };
  }
  keys.viewSecretKey = *(struct Crypto::SecretKey *) &key_hash;

  Crypto::secret_key_to_public_key(keys.spendSecretKey, keys.address.spendPublicKey);
  Crypto::secret_key_to_public_key(keys.viewSecretKey, keys.address.viewPublicKey);

  if (!m_core.get_miner().start(keys, static_cast<size_t>(req.threads_count))) {
    res.status = "Mining did not start (most likely it's already mining)";
    return true;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_stop_mining(const COMMAND_RPC_STOP_MINING::request& req, COMMAND_RPC_STOP_MINING::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  if (!m_core.get_miner().stop()) {
    res.status = "Not mining - nothing to stop";
    return true;
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  if (m_core.currency().isTestnet()) {
    m_p2p.sendStopSignal();
    res.status = CORE_RPC_STATUS_OK;
  } else {
    res.status = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
    return false;
  }
  return true;
}

bool RpcServer::on_get_fee_address(const COMMAND_RPC_GET_FEE_ADDRESS::request& req, COMMAND_RPC_GET_FEE_ADDRESS::response& res) {
  res.fee_address = m_fee_address;
  res.fee_amount = m_fee_amount;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_peer_list(const COMMAND_RPC_GET_PEER_LIST::request& req, COMMAND_RPC_GET_PEER_LIST::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  std::list<AnchorPeerlistEntry> pl_anchor;
  std::vector<PeerlistEntry> pl_wite;
  std::vector<PeerlistEntry> pl_gray;
  m_p2p.getPeerlistManager().get_peerlist_full(pl_anchor, pl_gray, pl_wite);
  for (const auto& pe : pl_anchor) {
    std::stringstream ss;
    ss << pe.adr;
    res.anchor_peers.push_back(ss.str());
  }
  for (const auto& pe : pl_wite) {
    std::stringstream ss;
    ss << pe.adr;
    res.white_peers.push_back(ss.str());
  }
  for (const auto& pe : pl_gray) {
    std::stringstream ss;
    ss << pe.adr;
    res.gray_peers.push_back(ss.str());
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_connections(const COMMAND_RPC_GET_CONNECTIONS::request& req, COMMAND_RPC_GET_CONNECTIONS::response& res) {
  if (m_restricted_rpc) {
    res.status = "Method disabled";
    return false;
  }

  std::vector<CryptoNoteConnectionContext> peers;
  if(!m_protocolQuery.getConnections(peers)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get connections" };
  }

  for (const auto& p : peers) {
    p2p_connection_entry c;

    c.version = p.version;
    c.state = get_protocol_state_string(p.m_state);
    c.connection_id = boost::lexical_cast<std::string>(p.m_connection_id);
    c.remote_ip = Common::ipAddressToString(p.m_remote_ip);
    c.remote_port = p.m_remote_port;
    c.is_incoming = p.m_is_income;
    c.started = static_cast<uint64_t>(p.m_started);
    c.remote_blockchain_height = p.m_remote_blockchain_height;
    c.last_response_height = p.m_last_response_height;

    res.connections.push_back(c);
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

//------------------------------------------------------------------------------------------------------------------------------
// JSON RPC methods
//------------------------------------------------------------------------------------------------------------------------------

bool RpcServer::on_blocks_list_json(const COMMAND_RPC_GET_BLOCKS_LIST::request& req, COMMAND_RPC_GET_BLOCKS_LIST::response& res) {
  if (m_core.getCurrentBlockchainHeight() <= req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight()) };
  }

  uint32_t print_blocks_count = 10;
  if(req.count <= BLOCK_LIST_MAX_COUNT)
    print_blocks_count = req.count;
  
  uint32_t last_height = req.height - print_blocks_count;
  if (req.height <= print_blocks_count)  {
    last_height = 0;
  }

  for (uint32_t i = req.height; i >= last_height; i--) {
    Crypto::Hash block_hash = m_core.getBlockIdByHeight(i);
    Block blk;
    if (!m_core.getBlockByHash(block_hash, blk)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by height. Height = " + std::to_string(i) + '.' };
    }

    size_t tx_cumulative_block_size;
    m_core.getBlockSize(block_hash, tx_cumulative_block_size);
    size_t blokBlobSize = getObjectBinarySize(blk);
    size_t minerTxBlobSize = getObjectBinarySize(blk.baseTransaction);
    difficulty_type blockDiff;
    m_core.getBlockDifficulty(static_cast<uint32_t>(i), blockDiff);

    block_short_response block_short;
    block_short.timestamp = blk.timestamp;
    block_short.height = i;
    block_short.hash = Common::podToHex(block_hash);
    block_short.cumulative_size = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
    block_short.transactions_count = blk.transactionHashes.size() + 1;
    block_short.difficulty = blockDiff;

    res.blocks.push_back(block_short);

    if (i == 0)
      break;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_alt_blocks_list_json(const COMMAND_RPC_GET_ALT_BLOCKS_LIST::request& req, COMMAND_RPC_GET_ALT_BLOCKS_LIST::response& res) {
  std::list<Block> alt_blocks;

  if (m_core.get_alternative_blocks(alt_blocks) && !alt_blocks.empty()) {
    for (const auto & b : alt_blocks) {
      Crypto::Hash block_hash = get_block_hash(b);
      uint32_t block_height = boost::get<BaseInput>(b.baseTransaction.inputs.front()).blockIndex;
      size_t tx_cumulative_block_size;
      m_core.getBlockSize(block_hash, tx_cumulative_block_size);
      size_t blokBlobSize = getObjectBinarySize(b);
      size_t minerTxBlobSize = getObjectBinarySize(b.baseTransaction);
      difficulty_type blockDiff;
      m_core.getBlockDifficulty(static_cast<uint32_t>(block_height), blockDiff);

      block_short_response block_short;
      block_short.timestamp = b.timestamp;
      block_short.height = block_height;
      block_short.hash = Common::podToHex(block_hash);
      block_short.cumulative_size = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
      block_short.transactions_count = b.transactionHashes.size() + 1;
      block_short.difficulty = blockDiff;

      res.alt_blocks.push_back(block_short);
    }
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_pool_short(const COMMAND_RPC_GET_TRANSACTIONS_POOL_SHORT::request& req, COMMAND_RPC_GET_TRANSACTIONS_POOL_SHORT::response& res) {
  auto pool = m_core.getMemoryPool();
  for (const CryptoNote::tx_memory_pool::TransactionDetails& txd : pool) {
    transaction_pool_response mempool_transaction;
    mempool_transaction.hash = Common::podToHex(txd.id);
    mempool_transaction.fee = txd.fee;
    mempool_transaction.amount_out = getOutputAmount(txd.tx);
    mempool_transaction.size = txd.blobSize;
    mempool_transaction.receive_time = txd.receiveTime;
    res.transactions.push_back(mempool_transaction);
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_pool(const COMMAND_RPC_GET_TRANSACTIONS_POOL::request& req, COMMAND_RPC_GET_TRANSACTIONS_POOL::response& res) {
  auto pool = m_core.getMemoryPool();

  for (const auto& txd : pool) {
    TransactionDetails transactionDetails;
    if (!blockchainExplorerDataBuilder.fillTransactionDetails(txd.tx, transactionDetails, txd.receiveTime)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't fill mempool tx details." };
    }
    res.transactions.push_back(std::move(transactionDetails));
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_pool_raw(const COMMAND_RPC_GET_RAW_TRANSACTIONS_POOL::request& req, COMMAND_RPC_GET_RAW_TRANSACTIONS_POOL::response& res) {
  auto pool = m_core.getMemoryPool();

  for (const auto& txd : pool) {
    res.transactions.push_back(tx_with_output_global_indexes());
    tx_with_output_global_indexes &e = res.transactions.back();

    e.hash = txd.id;
    e.height = boost::value_initialized<uint32_t>();
    e.block_hash = boost::value_initialized<Crypto::Hash>();
    e.timestamp = txd.receiveTime;
    e.transaction = *static_cast<const TransactionPrefix*>(&txd.tx);
    e.fee = txd.fee;
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_by_payment_id(const COMMAND_RPC_GET_TRANSACTIONS_BY_PAYMENT_ID::request& req, COMMAND_RPC_GET_TRANSACTIONS_BY_PAYMENT_ID::response& res) {
  if (!req.payment_id.size()) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong parameters, expected payment_id" };
  }

  Crypto::Hash paymentId;
  std::vector<Transaction> transactions;

  if (!parse_hash256(req.payment_id, paymentId)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse Payment ID: " + req.payment_id + '.' };
  }

  if (!m_core.getTransactionsByPaymentId(paymentId, transactions)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get transactions by Payment ID: " + req.payment_id + '.' };
  }

  for (const Transaction& tx : transactions) {
    transaction_short_response transaction_short;
    uint64_t amount_in = 0;
    get_inputs_money_amount(tx, amount_in);
    uint64_t amount_out = get_outs_money_amount(tx);

    transaction_short.hash = Common::podToHex(getObjectHash(tx));
    transaction_short.fee = amount_in - amount_out;
    transaction_short.amount_out = amount_out;
    transaction_short.size = getObjectBinarySize(tx);
    res.transactions.push_back(transaction_short);
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_getblockcount(const COMMAND_RPC_GETBLOCKCOUNT::request& req, COMMAND_RPC_GETBLOCKCOUNT::response& res) {
  res.count = m_core.getCurrentBlockchainHeight();
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_getblockhash(const COMMAND_RPC_GETBLOCKHASH::request& req, COMMAND_RPC_GETBLOCKHASH::response& res) {
  if (req.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong parameters, expected height" };
  }

  uint32_t h = static_cast<uint32_t>(req[0]);
  Crypto::Hash blockId = m_core.getBlockIdByHeight(h);
  if (blockId == NULL_HASH) {
    throw JsonRpc::JsonRpcError{ 
      CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(h) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight())
    };
  }

  res = Common::podToHex(blockId);
  return true;
}

namespace {
  uint64_t slow_memmem(void* start_buff, size_t buflen, void* pat, size_t patlen)
  {
    void* buf = start_buff;
    void* end = (char*)buf + buflen - patlen;
    while ((buf = memchr(buf, ((char*)pat)[0], buflen)))
    {
      if (buf>end)
        return 0;
      if (memcmp(buf, pat, patlen) == 0)
        return (char*)buf - (char*)start_buff;
      buf = (char*)buf + 1;
    }
    return 0;
  }
}

bool RpcServer::on_getblocktemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& req, COMMAND_RPC_GETBLOCKTEMPLATE::response& res) {
  if (req.reserve_size > TX_EXTRA_NONCE_MAX_COUNT) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE, "To big reserved size, maximum 255" };
  }

  AccountKeys keys = boost::value_initialized<AccountKeys>();

  Crypto::Hash key_hash;
  size_t size;
  if (!Common::fromHex(req.miner_spend_key, &key_hash, sizeof(key_hash), size) || size != sizeof(key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse miner spend key" };
  }
  keys.spendSecretKey = *(struct Crypto::SecretKey *) &key_hash;

  if (!Common::fromHex(req.miner_view_key, &key_hash, sizeof(key_hash), size) || size != sizeof(key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse miner view key" };
  }
  keys.viewSecretKey = *(struct Crypto::SecretKey *) &key_hash;

  Crypto::secret_key_to_public_key(keys.spendSecretKey, keys.address.spendPublicKey);
  Crypto::secret_key_to_public_key(keys.viewSecretKey, keys.address.viewPublicKey);

  Block b = boost::value_initialized<Block>();
  CryptoNote::BinaryArray blob_reserve;
  blob_reserve.resize(req.reserve_size, 0);
  if (!m_core.get_block_template(b, keys, res.difficulty, res.height, blob_reserve)) {
    logger(Logging::ERROR) << "Failed to create block template";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
  }

  BinaryArray block_blob = toBinaryArray(b);
  Crypto::PublicKey tx_pub_key = CryptoNote::getTransactionPublicKeyFromExtra(b.baseTransaction.extra);
  if (tx_pub_key == NULL_PUBLIC_KEY) {
    logger(Logging::ERROR) << "Failed to find tx pub key in coinbase extra";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to find tx pub key in coinbase extra" };
  }

  if (0 < req.reserve_size) {
    res.reserved_offset = slow_memmem((void*)block_blob.data(), block_blob.size(), &tx_pub_key, sizeof(tx_pub_key));
    if (!res.reserved_offset) {
      logger(Logging::ERROR) << "Failed to find tx pub key in blockblob";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
    }
    res.reserved_offset += sizeof(tx_pub_key) + 3; //3 bytes: tag for TX_EXTRA_TAG_PUBKEY(1 byte), tag for TX_EXTRA_NONCE(1 byte), counter in TX_EXTRA_NONCE(1 byte)
    if (res.reserved_offset + req.reserve_size > block_blob.size()) {
      logger(Logging::ERROR) << "Failed to calculate offset for reserved bytes";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
    }
  } else {
    res.reserved_offset = 0;
  }

  BinaryArray hashing_blob;
  if (!get_block_hashing_blob(b, hashing_blob)) {
    logger(Logging::ERROR) << "Failed to get blockhashing_blob";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to get blockhashing_blob" };
  }

  res.blocktemplate_blob = Common::toHex(block_blob);
  res.blockhashing_blob = Common::toHex(hashing_blob);
  res.status = CORE_RPC_STATUS_OK;

  return true;
}

bool RpcServer::on_get_currency_id(const COMMAND_RPC_GET_CURRENCY_ID::request& /*req*/, COMMAND_RPC_GET_CURRENCY_ID::response& res) {
  Crypto::Hash currencyId = m_core.currency().genesisBlockHash();
  res.currency_id_blob = Common::podToHex(currencyId);
  return true;
}

bool RpcServer::on_submitblock(const COMMAND_RPC_SUBMITBLOCK::request& req, COMMAND_RPC_SUBMITBLOCK::response& res) {
  if (req.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong param" };
  }

  BinaryArray blockblob;
  if (!Common::fromHex(req[0], blockblob)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB, "Wrong block blob" };
  }

  block_verification_context bvc = boost::value_initialized<block_verification_context>();

  m_core.handle_incoming_block_blob(blockblob, bvc, true, true);

  if (!bvc.m_added_to_main_chain) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_BLOCK_NOT_ACCEPTED, "Block not accepted" };
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}


namespace {
  uint64_t get_block_reward(const Block& blk) {
    uint64_t reward = 0;
    for (const TransactionOutput& out : blk.baseTransaction.outputs) {
      reward += out.amount;
    }
    return reward;
  }
}

void RpcServer::fill_block_header_response(const Block& blk, bool orphan_status, uint32_t height, const Crypto::Hash& hash, block_header_response& responce) {
  responce.major_version = blk.majorVersion;
  responce.minor_version = blk.minorVersion;
  responce.timestamp = blk.timestamp;
  responce.prev_hash = Common::podToHex(blk.previousBlockHash);
  responce.nonce = blk.nonce;
  responce.orphan_status = orphan_status;
  responce.height = height;
  responce.depth = m_core.getCurrentBlockchainHeight() - height - 1;
  responce.hash = Common::podToHex(hash);
  m_core.getBlockDifficulty(static_cast<uint32_t>(height), responce.difficulty);
  responce.reward = get_block_reward(blk);
}

bool RpcServer::on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res) {
  uint32_t last_block_height;
  Crypto::Hash last_block_hash;
  
  m_core.get_blockchain_top(last_block_height, last_block_hash);

  Block last_block;
  if (!m_core.getBlockByHash(last_block_hash, last_block)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get last block hash." };
  }
  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(last_block_height);
  bool is_orphaned = last_block_hash != tmp_hash;
  fill_block_header_response(last_block, is_orphaned, last_block_height, last_block_hash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res) {
  Crypto::Hash block_hash;

  if (!parse_hash256(req.hash, block_hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of block hash. Hex = " + req.hash + '.' };
  }

  Block blk;
  if (!m_core.getBlockByHash(block_hash, blk)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get block by hash. Hash = " + req.hash + '.' };
  }

  if (blk.baseTransaction.inputs.front().type() != typeid(BaseInput)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: coinbase transaction in the block has the wrong type" };
  }

  uint32_t block_height = boost::get<BaseInput>(blk.baseTransaction.inputs.front()).blockIndex;
  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(block_height);
  bool is_orphaned = block_hash != tmp_hash;
  fill_block_header_response(blk, is_orphaned, block_height, block_hash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res) {
  if (m_core.getCurrentBlockchainHeight() <= req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight()) };
  }

  Crypto::Hash block_hash = m_core.getBlockIdByHeight(static_cast<uint32_t>(req.height));
  Block blk;
  if (!m_core.getBlockByHash(block_hash, blk)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get block by height. Height = " + std::to_string(req.height) + '.' };
  }
  
  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(req.height);
  bool is_orphaned = block_hash != tmp_hash;
  fill_block_header_response(blk, is_orphaned, req.height, block_hash, res.block_header);
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_timestamp_by_height(const COMMAND_RPC_GET_BLOCK_TIMESTAMP_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_TIMESTAMP_BY_HEIGHT::response& res) {
  if (m_core.getCurrentBlockchainHeight() <= req.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(req.height) + ", current blockchain height = " + std::to_string(m_core.getCurrentBlockchainHeight()) };
  }

  res.status = CORE_RPC_STATUS_OK;

  m_core.getBlockTimestamp(req.height, res.timestamp);

  return true;
}

bool RpcServer::on_check_transaction_key(const COMMAND_RPC_CHECK_TRANSACTION_KEY::request& req, COMMAND_RPC_CHECK_TRANSACTION_KEY::response& res) {
  // parse txid
  Crypto::Hash txid;
  if (!parse_hash256(req.transaction_id, txid)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse txid" };
  }
  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.currency().parseAccountAddressString(req.address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.address + '.' };
  }
  // parse txkey
  Crypto::Hash tx_key_hash;
  size_t size;
  if (!Common::fromHex(req.transaction_key, &tx_key_hash, sizeof(tx_key_hash), size) || size != sizeof(tx_key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse txkey" };
  }
  Crypto::SecretKey tx_key = *(struct Crypto::SecretKey *) &tx_key_hash;

  // fetch tx
  Transaction tx;
  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(txid);
  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(tx_ids, txs, missed_txs, true);

  if (!missed_txs.empty() || 1 != txs.size()) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Couldn't find transaction " + req.transaction_id };
  }
  tx = txs.front();
  CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);

  // obtain key derivation
  Crypto::KeyDerivation derivation;
  if (!Crypto::generate_key_derivation(address.viewPublicKey, tx_key, derivation))
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to generate key derivation from supplied parameters" };
  }
  
  // look for outputs
  uint64_t received(0);
  size_t keyIndex(0);
  std::vector<TransactionOutput> outputs;
  try {
    for (const TransactionOutput& o : transaction.outputs) {
      if (o.target.type() == typeid(KeyOutput)) {
        const KeyOutput out_key = boost::get<KeyOutput>(o.target);
        Crypto::PublicKey pubkey;
        derive_public_key(derivation, keyIndex, address.spendPublicKey, pubkey);
        if (pubkey == out_key.key) {
          received += o.amount;
          outputs.push_back(o);
        }
      }
      ++keyIndex;
    }
  }
  catch (...)
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
  }
  res.amount = received;
  res.outputs = outputs;
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_check_transaction_with_view_key(const COMMAND_RPC_CHECK_TRANSACTION_WITH_PRIVATE_VIEW_KEY::request& req, COMMAND_RPC_CHECK_TRANSACTION_WITH_PRIVATE_VIEW_KEY::response& res) {
  // parse txid
  Crypto::Hash txid;
  if (!parse_hash256(req.transaction_id, txid)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse txid" };
  }
  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.currency().parseAccountAddressString(req.address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.address + '.' };
  }
  // parse view key
  Crypto::Hash view_key_hash;
  size_t size;
  if (!Common::fromHex(req.view_key, &view_key_hash, sizeof(view_key_hash), size) || size != sizeof(view_key_hash)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse private view key" };
  }
  Crypto::SecretKey viewKey = *(struct Crypto::SecretKey *) &view_key_hash;

  // fetch tx
  Transaction tx;
  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(txid);
  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(tx_ids, txs, missed_txs, true);

  if (!missed_txs.empty() || 1 != txs.size()) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Couldn't find transaction " + req.transaction_id };
  }
  tx = txs.front();
  CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);
  
  // get tx pub key
  Crypto::PublicKey txPubKey = getTransactionPublicKeyFromExtra(transaction.extra);

  // obtain key derivation
  Crypto::KeyDerivation derivation;
  if (!Crypto::generate_key_derivation(txPubKey, viewKey, derivation))
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to generate key derivation from supplied parameters" };
  }

  // look for outputs
  uint64_t received(0);
  size_t keyIndex(0);
  std::vector<TransactionOutput> outputs;
  try {
    for (const TransactionOutput& o : transaction.outputs) {
      if (o.target.type() == typeid(KeyOutput)) {
        const KeyOutput out_key = boost::get<KeyOutput>(o.target);
        Crypto::PublicKey pubkey;
        derive_public_key(derivation, keyIndex, address.spendPublicKey, pubkey);
        if (pubkey == out_key.key) {
          received += o.amount;
          outputs.push_back(o);
        }
      }
      ++keyIndex;
    }
  }
  catch (...)
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
  }
  res.amount = received;
  res.outputs = outputs;
  
  Crypto::Hash blockHash;
  uint32_t blockHeight;
  if (m_core.getBlockContainingTx(txid, blockHash, blockHeight)) {
    res.confirmations = m_protocolQuery.getObservedHeight() - blockHeight;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_check_transaction_proof(const COMMAND_RPC_CHECK_TRANSACTION_PROOF::request& req, COMMAND_RPC_CHECK_TRANSACTION_PROOF::response& res) {
  // parse txid
  Crypto::Hash txid;
  if (!parse_hash256(req.transaction_id, txid)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse txid" };
  }
  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.currency().parseAccountAddressString(req.destination_address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.destination_address + '.' };
  }
  // parse pubkey r*A & signature
  std::string decoded_data;
  uint64_t prefix;
  if (!Tools::Base58::decode_addr(req.signature, prefix, decoded_data) || prefix != CryptoNote::parameters::CRYPTONOTE_TX_PROOF_BASE58_PREFIX) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Transaction proof decoding error" };
  }
  Crypto::PublicKey rA;
  Crypto::Signature sig;
  std::string rA_decoded = decoded_data.substr(0, sizeof(Crypto::PublicKey));
  std::string sig_decoded = decoded_data.substr(sizeof(Crypto::PublicKey), sizeof(Crypto::Signature));

  memcpy(&rA, rA_decoded.data(), sizeof(Crypto::PublicKey));
  memcpy(&sig, sig_decoded.data(), sizeof(Crypto::Signature));

  // fetch tx pubkey
  Transaction tx;

  std::vector<uint32_t> out;
  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(txid);
  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(tx_ids, txs, missed_txs, true);

  if (!missed_txs.empty() || 1 != txs.size()) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Couldn't find transaction " + req.transaction_id };
  }
  tx = txs.front();
  CryptoNote::TransactionPrefix transaction = *static_cast<const TransactionPrefix*>(&tx);

  Crypto::PublicKey R = getTransactionPublicKeyFromExtra(transaction.extra);
  if (R == NULL_PUBLIC_KEY)
  {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Tx pubkey was not found" };
  }

  // check signature
  bool r = Crypto::check_tx_proof(txid, R, address.viewPublicKey, rA, sig);
  res.signature_valid = r;

  if (r) {

    // obtain key derivation by multiplying scalar 1 to the pubkey r*A included in the signature
    Crypto::KeyDerivation derivation;
    if (!Crypto::generate_key_derivation(rA, Crypto::EllipticCurveScalar2SecretKey(Crypto::I), derivation)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to generate key derivation" };
    }

    // look for outputs
    uint64_t received(0);
    size_t keyIndex(0);
    std::vector<TransactionOutput> outputs;
    try {
      for (const TransactionOutput& o : transaction.outputs) {
        if (o.target.type() == typeid(KeyOutput)) {
          const KeyOutput out_key = boost::get<KeyOutput>(o.target);
          Crypto::PublicKey pubkey;
          derive_public_key(derivation, keyIndex, address.spendPublicKey, pubkey);
          if (pubkey == out_key.key) {
            received += o.amount;
            outputs.push_back(o);
          }
        }
        ++keyIndex;
      }
    }
    catch (...)
    {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
    }
    res.received_amount = received;
    res.outputs = outputs;

    Crypto::Hash blockHash;
    uint32_t blockHeight;
    if (m_core.getBlockContainingTx(txid, blockHash, blockHeight)) {
      res.confirmations = m_protocolQuery.getObservedHeight() - blockHeight;
    }
  }
  else {
    res.received_amount = 0;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_check_reserve_proof(const COMMAND_RPC_CHECK_RESERVE_PROOF::request& req, COMMAND_RPC_CHECK_RESERVE_PROOF::response& res) {
  // parse address
  CryptoNote::AccountPublicAddress address;
  if (!m_core.currency().parseAccountAddressString(req.address, address)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address " + req.address + '.' };
  }
  
  // parse sugnature
  std::string decoded_data;
  uint64_t prefix;
  if (!Tools::Base58::decode_addr(req.signature, prefix, decoded_data) || prefix != CryptoNote::parameters::CRYPTONOTE_RESERVE_PROOF_BASE58_PREFIX) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Reserve proof decoding error" };
  }
  BinaryArray ba(decoded_data.begin(), decoded_data.end());
  reserve_proof proof_decoded;
  if (!fromBinaryArray(proof_decoded, ba)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Reserve proof BinaryArray decoding error" };
  }

  std::vector<reserve_proof_entry>& proofs = proof_decoded.proofs;
  
  // compute signature prefix hash
  std::string prefix_data = req.message;
  prefix_data.append((const char*)&address, sizeof(CryptoNote::AccountPublicAddress));
  for (size_t i = 0; i < proofs.size(); ++i) {
    prefix_data.append((const char*)&proofs[i].key_image, sizeof(Crypto::PublicKey));
  }
  Crypto::Hash prefix_hash;
  Crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

  // fetch txes
  std::vector<Crypto::Hash> transactionHashes;
  for (size_t i = 0; i < proofs.size(); ++i) {
    transactionHashes.push_back(proofs[i].transaction_id);
  }
  // first check against height if provided to spare further checks
  // in case request is to check proof of funds that didn't exist yet at this height
  if (req.height != 0) {
    for (const auto& h : transactionHashes) {
      uint32_t tx_height;
      if (!m_core.getTransactionHeight(h, tx_height)) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "Couldn't find block index containing transaction " + Common::podToHex(h) + " of reserve proof" };
      }

      if (req.height < tx_height) {
        throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Funds from transaction "
          + Common::podToHex(h) + " in block " + std::to_string(tx_height) + " didn't exist at requested height" };
      }
    }
  }
  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(transactionHashes, txs, missed_txs);
  if (!missed_txs.empty()) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Couldn't find some transactions of reserve proof" };
  }
  std::vector<Transaction> transactions;
  std::copy(txs.begin(), txs.end(), std::inserter(transactions, transactions.end()));

  // check spent status
  res.total = 0;
  res.spent = 0;
  res.locked = 0;
  for (size_t i = 0; i < proofs.size(); ++i) {
    const reserve_proof_entry& proof = proofs[i];

    CryptoNote::TransactionPrefix tx = *static_cast<const TransactionPrefix*>(&transactions[i]);
    
    bool unlocked = m_core.is_tx_spendtime_unlocked(tx.unlockTime, req.height);

    if (proof.index_in_transaction >= tx.outputs.size()) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "index_in_tx is out of bound" };
    }

    const KeyOutput out_key = boost::get<KeyOutput>(tx.outputs[proof.index_in_transaction].target);

    // get tx pub key
    Crypto::PublicKey txPubKey = getTransactionPublicKeyFromExtra(tx.extra);

    // check singature for shared secret
    if (!Crypto::check_tx_proof(prefix_hash, address.viewPublicKey, txPubKey, proof.shared_secret, proof.shared_secret_sig)) {
      //throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to check singature for shared secret" };
      res.good = false;
      return true;
    }

    // check signature for key image
    const std::vector<const Crypto::PublicKey *>& pubs = { &out_key.key };
    if (!Crypto::check_ring_signature(prefix_hash, proof.key_image, &pubs[0], 1, &proof.key_image_sig)) {
      //throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to check signature for key image" };
      res.good = false;
      return true;
    }

    // check if the address really received the fund
    Crypto::KeyDerivation derivation;
    if (!Crypto::generate_key_derivation(proof.shared_secret, Crypto::EllipticCurveScalar2SecretKey(Crypto::I), derivation)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Failed to generate key derivation" };
    }
    try {
      Crypto::PublicKey pubkey;
      derive_public_key(derivation, proof.index_in_transaction, address.spendPublicKey, pubkey);
      if (pubkey == out_key.key) {
        uint64_t amount = tx.outputs[proof.index_in_transaction].amount;
        res.total += amount;

        if (!unlocked) {
          res.locked += amount;
        }

        if (req.height != 0) {
          if (m_core.is_key_image_spent(proof.key_image, req.height)) {
            res.spent += amount;
          }
        } else {
          if (m_core.is_key_image_spent(proof.key_image)) {
            res.spent += amount;
          }
        }
      }
    }
    catch (...)
    {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Unknown error" };
    }  
  }

  // check signature for address spend keys
  Crypto::Signature sig = proof_decoded.signature;
  if (!Crypto::check_signature(prefix_hash, address.spendPublicKey, sig)) {
    res.good = false;
    return true;
  }

  res.good = true;

  return true;
}

bool RpcServer::on_validate_address(const COMMAND_RPC_VALIDATE_ADDRESS::request& req, COMMAND_RPC_VALIDATE_ADDRESS::response& res) {
  AccountPublicAddress acc = boost::value_initialized<AccountPublicAddress>();
  bool r = m_core.currency().parseAccountAddressString(req.address, acc);
  res.is_valid = r;
  if (r) {
    res.address = m_core.currency().accountAddressAsString(acc);
    res.spend_public_key = Common::podToHex(acc.spendPublicKey);
    res.view_public_key = Common::podToHex(acc.viewPublicKey);
  }
  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_verify_message(const COMMAND_RPC_VERIFY_MESSAGE::request& req, COMMAND_RPC_VERIFY_MESSAGE::response& res) {
  AccountPublicAddress acc = boost::value_initialized<AccountPublicAddress>();
  if (!m_core.currency().parseAccountAddressString(req.address, acc)) {
    throw JsonRpc::JsonRpcError{CORE_RPC_ERROR_CODE_WRONG_PARAM, "Failed to parse address" };
  }

  // could just've used this but detailed errors might be more handy
  //res.sig_valid = CryptoNote::verifyMessage(req.message, acc, req.signature, logger.getLogger());

  std::string decoded;
  Crypto::Signature s;
  uint64_t prefix;
  if (!Tools::Base58::decode_addr(req.signature, prefix, decoded) || prefix != CryptoNote::parameters::CRYPTONOTE_KEYS_SIGNATURE_BASE58_PREFIX) {
    throw JsonRpc::JsonRpcError{CORE_RPC_ERROR_CODE_WRONG_PARAM, "Signature decoding error" };
  }

  if (sizeof(s) != decoded.size()) {
    throw JsonRpc::JsonRpcError{CORE_RPC_ERROR_CODE_WRONG_PARAM, "Signature size wrong" };
    return false;
  }

  Crypto::Hash hash;
  Crypto::cn_fast_hash(req.message.data(), req.message.size(), hash);

  memcpy(&s, decoded.data(), sizeof(s));
  res.sig_valid = Crypto::check_signature(hash, acc.spendPublicKey, s);

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_resolve_open_alias(const COMMAND_RPC_RESOLVE_OPEN_ALIAS::request& req, COMMAND_RPC_RESOLVE_OPEN_ALIAS::response& res) {
  try {
    res.address = Common::resolveAlias(req.url);

    AccountPublicAddress ignore;
    if (!m_core.currency().parseAccountAddressString(res.address, ignore)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Address \"" + res.address + "\" is invalid" };
    }
  }
  catch (std::exception& e) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Couldn't resolve alias: " + std::string(e.what()) };
    return true;
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

}
