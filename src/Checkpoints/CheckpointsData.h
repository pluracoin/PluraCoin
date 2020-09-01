// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2020, The Karbo developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <cstddef>
#include <initializer_list>

namespace CryptoNote {

struct CheckpointData {
  uint32_t height;
  const char* blockId;
};

const std::initializer_list<CheckpointData> CHECKPOINTS = { 
    {3000, "bec581b36c62e08ffd7520b7784366ec34b600edda6418a6893ef0fc7ecb8d91"},
    {10000, "f199869dd20c764353585fbf061361c194ac289eb68b21c0bfb4d7c8d4492beb"},
    {20000, "b1f574bfd11e67e64041791c45fab84b80ba18739e54022d0c1d09c74dd74fe4"},
    {30000, "e6687632048c3db6214c433a18760d132bd656c928037aea8fd78b2cd9ebc388"},
    {40000, "9dabc1aedf31fea10d556c953706348bb1144f9ee0a53f78f56385ef2015fb24"},
    {50000, "d0457b4bcf6bcc4cb42d94271f5a5c40273f3fd9c12bc5f5c398ce4d69d0e4bf"},
    {60000, "f88662c0f2b842ecbd4f57d53e7cd210d9dab9ebd91270ccbacc6de522b53427"},
    {70000, "2f2706b936fee7bd46f93b0d529b7233675ac137b434415b0b1f74eee50fc44b"},
    {80000, "3bae6e8ef6bb03a0d21b593188d48b8aa61f4fcddaeea7fab099ba3d9d59515f"},
    {90000, "45fb3e70defa0c0e1a1074466f8a29563738fdf8b54daa0b756625700f0c6e90"},
    {100000, "f17e875f4dd5b8e48f01c33f9420740e45ab279b4731365acbeb10e230209613"},
    {110000, "f50905a01d4706d3b69419b0b255da055c93d46a84689563a20b1609126a3597"},
    {130000, "1f0d85bea1758ec7d347f3b72d71fa45b994a5afd77a74a656f65fa95858c716"},
    {140000, "082e73ec314f08eec0df93de9cf549a8ac2fadc1cfb76a87e434298eb412d7ed"},
    {150000, "b1a2b72767718668bf6b06a338918ca0d034ee25386e24883c088111251b8dc2"},
    {161170, "a426bb1abcfa32d13017ca5e662a6eb2e6d0b006b56d85368a5cde7cbcd24b8e"},
    {161500, "969170b96fbd1fce93229a9cc4d18419a52f6c4de299ca6f70643612ce7543a0"},
    {165000, "b369f35f9ef33f374e307d849faa72b48ba05ea6860b9fb0b1435ae6a4e40cf1"},
    {170000, "9e060b20ed9ab12fea63c84a83721cc1db7af4d7c104ca49eb0eb188ca50c79f"},
    {180000, "c3821860802c8a6b57de86f42772edac2e2a0c640b7982fc4c8767464c9537b5"},
    {190000, "4b7e9611a89d9df558d67ebf83436c21376396b913a98982611b21fe9b46a011"},
    {197000, "c474faae20a40ee376e6a8631e20536584238f761a1d43c7a6a5271498a610be"},
    {225000, "8fd5317102b35381afce2738aeb71e083545152386aa6679dd651d278b3cce07"},
    {230000, "cdae855ee64249bb4763e2bdef583f2dafddb71b97bd340addfedef97980a730"},
    {234000, "f57329344e7c43658cd816fb343b316c74eb807fdf1a029acd8b7dfdcd3abf6f"},
    {245000, "d28f1fff23ad30ec2f118fa58d819353b9523fc290319e2dc275672e4eacacc4"},
    {280000, "3ee49db6b7797eb05fb33378f550a5bce1eb75db288f5bbd8c86096e0ea006c9"},
    {300000, "8a0fabd20ab7e4c3612a2c7b45637488345226b8e42b9406e006c4384e753326"},
    {325000, "e1fccd7ee89374ade6650d7e1a01710abd471f73bf627b772851dbd9c34cc53a"},
    {350000, "bc1a62a7b5bd73a96e375c6ae88217611786251b9acab245218f6465d0585a70"},
    {360500, "0c4023df7712c6457d90e7d50b7528d4ffb6d4ca390dee3dae8afece087bfc5c"}
};
  
}
