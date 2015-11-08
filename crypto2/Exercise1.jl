# Copyright (c) 2015 Mateusz Pyzik, all rights reserved.
function getByte(binary)
  value :: Char = 0
  for bit in binary
    value += value + (bit - '0')
  end
  return value
end

function getInput(path)
  INPUT = open(path)
  cs = Array[]
  i = 1
  for line in eachline(INPUT)
    push!(cs, Char[])
    for group in eachmatch(r"[01]{8}", line)
      byte = getByte(group.match)
      push!(cs[i], byte)
    end
    i += 1
  end
  close(INPUT)
  return cs
end

(c, cs) = begin
  cs = getInput("G:/Studia/Kryptografia i bezpieczeństwo/1.txt")
  c = pop!(cs)
  for i = 1:length(cs)
    resize!(cs[i], length(c))
    for j = 1:length(c)
      cs[i][j] $= c[j]
    end
  end
  (c, cs)
end

(text, freqs) = begin
  pred0(x) = isalnum(x) || x in " \":,.!?"
  pred1(x) = islower(x) || x == ' '
  alphabet = filter(pred0, map(char, 0:127))
  text = Char[]
  freqs = [Dict{Char,Int}() for j = 1:length(c)]
  for j = 1:length(c)
    maxa = '\0'
    max = 0
    for a in alphabet
      counter = 0
      for i = 1:length(cs)
        if pred1(cs[i][j] $ a)
          counter = counter + 1
        end
      end
      freqs[j][a] = counter
      if counter > max
        max = counter
        maxa = a
      end
    end
    push!(text, maxa)
  end
  text = ascii(text)
  println(text)
  (text, freqs)
end

msg = "\"Spot wyborczy\" lidera Bayer Full: \"Jestem na cmentarzu. Do 67. roku zycia malo kto dozyl!\""
key = map($, msg, c)
ms = map(ci -> ascii(map((x,y,z) -> x $ y $ z, c, ci, key)), cs)
for m in ms
  println(m)
end
