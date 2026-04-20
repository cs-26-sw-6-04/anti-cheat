/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: MIT
 */

#include "random.hpp"

#include <array>
#include <random>

namespace ac {

std::string random_token() {
  static thread_local std::mt19937_64 rng{std::random_device{}()};
  std::uniform_int_distribution<uint64_t> dist;

  constexpr std::array<char, 16> hex{'0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  uint64_t v = dist(rng);
  std::string out = "CTF{";
  for (int i = 15; i >= 0; --i)
    out.push_back(hex[(v >> (i * 4)) & 0xf]);
  out.push_back('}');
  return out;
}

} // namespace ac
