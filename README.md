# JavaScript Zrim Netfilter

## iptables-save Parser

It is more convenient to parse the output from ipatables-save than the 
iptables commands.

The parser generate a rule tree:

With:
<pre>
Table
  |_ Chain
      |_ Rule
</pre>

## Rule

A rule contains:
- The chain reference
- Source
- Destination
- Input interface
- Output interface
- The matches (Array)
- The target (Object)
- The goto (Object)

## Rule Match definition

Defines:
- The name
- The aliases
- The possible arguments

### Argument

Define:
- The name
- The alias
- If accept value or not



