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

#pragma once

#include <System/Dispatcher.h>

namespace System {

class ContextGroup {
public:
  explicit ContextGroup(Dispatcher& dispatcher);
  ContextGroup(const ContextGroup&) = delete;
  ContextGroup(ContextGroup&& other);
  ~ContextGroup();
  ContextGroup& operator=(const ContextGroup&) = delete;
  ContextGroup& operator=(ContextGroup&& other);
  void interrupt();
  void spawn(std::function<void()>&& procedure);
  void wait();

private:
  Dispatcher* dispatcher;
  NativeContextGroup contextGroup;
};

}
