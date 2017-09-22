const _ = require('lodash'),
  BaseObject = require('js-zrim-core').BaseObject,
  async = require('async'),
  util = require('util');


/**
 * @typedef {Object} IptablesSaveParser~CommandArguments
 * @property {string} [protocol] The protocol to use
 */
/**
 * Contains the command information
 * @typedef {Object} IptablesSaveParser~Command
 * @property {string[]} rawArguments The raw command arguments
 * @property {IptablesSaveParser~CommandArguments} arguments The command parsed argument
 */
/**
 * Contains the table information
 * @typedef {Object} IptablesSaveParser~Table
 * @property {string} name The chain name
 */
/**
 * Contains the chain information
 * @typedef {Object} IptablesSaveParser~Chain
 * @property {string} name The chain name
 * @property {string} defaultPolicy The default policy
 */
/**
 * @typedef {Object} IptablesSaveParser.parseFromRawLines~ParseLineContext
 * @property {string} lineType The type
 * @property {string} rawLine The raw line data
 * @property {string} comment The comment in case the type is 'comment'
 * @property {IptablesSaveParser~Table} table The table information
 * @property {IptablesSaveParser~Chain} chain The chain information
 * @property {IptablesSaveParser~Command} command The command information
 */


/**
 * Iptables Save parser. This class will help to parse the content returned by
 * iptables-save.
 * @constructor
 */
function IptablesSaveParser() {
  if (!(this instanceof IptablesSaveParser)) {
    return new(Function.prototype.bind.apply(IptablesSaveParser, Array.prototype.concat.apply([null], arguments)));
  }

  BaseObject.apply(this, arguments);
}

BaseObject._applyPrototypeTo(IptablesSaveParser);


/**
 * @typedef {Object} IptablesSaveParser.parseFromRawLines~Options
 * @property {string[]} rawLines The lines returns by iptables-save
 */
/**
 * Parse the data using all lines
 * @param {IptablesSaveParser.parseFromRawLines~Options} options The options
 * @return {Promise}
 */
IptablesSaveParser.prototype.parseFromRawLines = function (options) {
  const __pretty_name__ = 'parseFromRawLines';

  return new Promise((resolve, reject) => {

    const parseLineContexts = [];

    let currentTableName; // Help to know the current table name
    const handleRawLine = (rawLine, rawLineIndex, callback) => {
      this.logger.debug("[%s] Start parsing the raw line %d", __pretty_name__, rawLineIndex);

      const parseLineContext = {
        lineType: 'unknown',
        rawLine: rawLine
      };
      parseLineContexts.push(parseLineContext);

      if (rawLine.trim().length === 0) {
        parseLineContext.lineType = 'empty';
        setImmediate(callback);
      } else if (rawLine.toLowerCase() === 'commit') {
        parseLineContext.lineType = 'commit';
        currentTableName = undefined;
        setImmediate(callback);
      } else {
        switch (rawLine.substr(0, 1).toLowerCase()) {
          case '#':
            parseLineContext.lineType = 'comment';
            parseLineContext.comment = rawLine.substr(1).trim();
            if (currentTableName) {
              parseLineContext.originalTableName = currentTableName;
            }

            setImmediate(callback);
            break;
          case '*':
            parseLineContext.lineType = 'table';
            parseLineContext.table = {
              name: rawLine.substr(1).trim()
            };
            currentTableName = parseLineContext.table.name;
            setImmediate(callback);
            break;
          case ':':
            parseLineContext.lineType = 'chain';

            const chainInfoMatches = rawLine.match(/^:([a-z0-9_-]+)\s+([a-z0-9_-]+)\s+/i);
            if (_.isArray(chainInfoMatches) && chainInfoMatches.length > 0) {
              parseLineContext.chain = {
                name: chainInfoMatches[1],
                defaultPolicy: chainInfoMatches[2] === '-' ? undefined : chainInfoMatches[2]
              };
              if (currentTableName) {
                parseLineContext.originalTableName = currentTableName;
              }

              setImmediate(callback);
            } else {
              // Error
              setImmediate(callback, new Error(util.format("Cannot parse chain: %s", rawLine)));
            }
            break;
          default:
            parseLineContext.lineType = 'command';
            parseLineContext.command = {
              rawArguments: _.split(rawLine, ' '),
              arguments: {
                matches: {}
              }
            };
            if (currentTableName) {
              parseLineContext.originalTableName = currentTableName;
            }

            this._parseRawCommand({
              context: parseLineContext
            })
              .then(() => setImmediate(callback))
              .catch(error => setImmediate(callback, error));
            break;
        }
      }
    };

    async.eachOfSeries(options.rawLines, handleRawLine, error => {
      console.log(JSON.stringify(parseLineContexts, null, 2));
      if (error) {
        return reject(error);
      } else {
        return resolve();
      }
    });
  });
};

/**
 * @typedef {Object} IptablesSaveParser._parseRawCommand~Options
 * @property {IptablesSaveParser.parseFromRawLines~ParseLineContext} context The context
 */
/**
 * Parse a raw command
 * @param {IptablesSaveParser._parseRawCommand~Options} options The options
 * @return {Promise}
 */
IptablesSaveParser.prototype._parseRawCommand = function (options) {

  return new Promise((resolve, reject) => {
    const parseLineContext = options.context,
      command = parseLineContext.command,
      rawArguments = command.rawArguments,
      commandArguments = command.arguments;

    const rawArgumentsLength = rawArguments.length;

    // Keep to know if use negative
    let enableNegation = false;

    // Use this current function to be like a async loop
    let currentRawArgumentsIndex = 0;
    const doHandleLoop = () => {
      if (currentRawArgumentsIndex >= rawArgumentsLength) {
        // loop done
        setImmediate(resolve);
        return;
      }

      let rawArgument = rawArguments[currentRawArgumentsIndex];

      if (rawArgument === '!') {
        enableNegation = true;
        ++currentRawArgumentsIndex;
        return setImmediate(doHandleLoop);
      }

      switch (rawArgument) {
        case '-A':
        case '--append':
          commandArguments.insertType = 'append';
          commandArguments.chainName = rawArguments[currentRawArgumentsIndex + 1];
          currentRawArgumentsIndex += 2;
          setImmediate(doHandleLoop);
          break;
        case '-p':
        case '--protocol':
          // [!] protocol
          commandArguments.protocol = (enableNegation ? '!' : '') + rawArguments[currentRawArgumentsIndex + 1];
          currentRawArgumentsIndex += 2;
          setImmediate(doHandleLoop);
          break;
        case '-s':
        case '--source':
          // [!] address[/mask]
          commandArguments.source = (enableNegation ? '!' : '') + rawArguments[currentRawArgumentsIndex + 1];
          currentRawArgumentsIndex += 2;
          setImmediate(doHandleLoop);
          break;
        case '-d':
        case '--destination':
          // [!] address[/mask]
          commandArguments.destination = (enableNegation ? '!' : '') + rawArguments[currentRawArgumentsIndex + 1];
          currentRawArgumentsIndex += 2;
          setImmediate(doHandleLoop);
          break;
        case '-j':
        case '--jump':
          // target
          const parseJumpOptions = {
            context: parseLineContext,
            rawArgumentsIndex: currentRawArgumentsIndex,
            rawArgumentsLength: rawArgumentsLength
          };
          this._parseRawJumpCommand(parseJumpOptions)
            .then(response => {
              currentRawArgumentsIndex = response.newArgumentsIndex;
              setImmediate(doHandleLoop);
            })
            .catch(error => setImmediate(reject, error));
          break;
        case '-g':
        case '--goto':
          // chain
          const parseGotoOptions = {
            context: parseLineContext,
            rawArgumentsIndex: currentRawArgumentsIndex,
            rawArgumentsLength: rawArgumentsLength
          };
          this._parseRawGotoCommand(parseGotoOptions)
            .then(response => {
              currentRawArgumentsIndex = response.newArgumentsIndex;
              setImmediate(doHandleLoop);
            })
            .catch(error => setImmediate(reject, error));
          break;
        case '-i':
        case '--in-interface':
          // [!] name
          commandArguments.inInterface = (enableNegation ? '!' : '') + rawArguments[currentRawArgumentsIndex + 1];
          currentRawArgumentsIndex += 2;
          setImmediate(doHandleLoop);
          break;
        case '-o':
        case '--out-interface':
          // [!] name
          commandArguments.outInterface = (enableNegation ? '!' : '') + rawArguments[currentRawArgumentsIndex + 1];
          currentRawArgumentsIndex += 2;
          setImmediate(doHandleLoop);
          break;
        case '-f':
        case '--fragment':
          // [!] -f, --fragment
          commandArguments.fragment = (enableNegation ? '!' : '') + rawArguments[currentRawArgumentsIndex + 1];
          currentRawArgumentsIndex += 2;
          setImmediate(doHandleLoop);
          break;
        case  '-c':
        case '--set-counters':
          // -c, --set-counters PKTS BYTES
          commandArguments.packetPerBytes = rawArguments[currentRawArgumentsIndex + 2];
          commandArguments.packetCounter = rawArguments[currentRawArgumentsIndex + 3];
          currentRawArgumentsIndex += 3;
          setImmediate(doHandleLoop);
          break;
        case '-m':
        case '--match':
          //
          // Find the last index, until -j, -m, -g
          let endIndex = rawArgumentsLength;
          for (let i = currentRawArgumentsIndex + 1; i < rawArgumentsLength; ++i) {
            if (_.indexOf(['-j', '--jump', '-g', '--goto', '-m', '--match'], rawArguments[i]) >= 0) {
              endIndex = i;
              break;
            }
          }

          const parseMatchOptions = {
            context: parseLineContext,
            rawArgumentsIndex: currentRawArgumentsIndex,
            matchLength: endIndex - currentRawArgumentsIndex
          };
          this._parseRawMatchCommand(parseMatchOptions)
            .then(response => {
              // currentRawArgumentsIndex = response.newArgumentsIndex;
              currentRawArgumentsIndex = endIndex;
              setImmediate(doHandleLoop);
            })
            .catch(error => setImmediate(reject, error));
          break;
        default:
          setImmediate(reject, new Error(util.format('Unhandled arg %s', rawArgument)));
          break;
      }

      enableNegation = false; // Remove the negation
    }; // End of the handle loop

    setImmediate(doHandleLoop);
  });
};

/**
 * @typedef {Object} IptablesSaveParser._parseRawJumpCommand~OnResolve
 * @property {number} newArgumentsIndex The new index to set
 */
/**
 * @typedef {Object} IptablesSaveParser._parseRawJumpCommand~Options
 * @property {IptablesSaveParser.parseFromRawLines~ParseLineContext} context The context
 * @property {number} rawArgumentsIndex The current arguments index that point to -j
 * @property {number} rawArgumentsLength The raw argument length
 */
/**
 * Parse a raw command
 * @param {IptablesSaveParser._parseRawJumpCommand~Options} options The options
 * @return {Promise} {@link IptablesSaveParser._parseRawJumpCommand~OnResolve} on resolve
 */
IptablesSaveParser.prototype._parseRawJumpCommand = function (options) {

  return new Promise(resolve => {
    options.context.command.arguments.jump = {
      targetName: options.context.command.rawArguments[options.rawArgumentsIndex + 1]
    };

    // Must be the last one
    resolve({
      newArgumentsIndex: options.rawArgumentsLength
    });
  });
};

/**
 * @typedef {Object} IptablesSaveParser._parseRawGotoCommand~OnResolve
 * @property {number} newArgumentsIndex The new index to set
 */
/**
 * @typedef {Object} IptablesSaveParser._parseRawGotoCommand~Options
 * @property {IptablesSaveParser.parseFromRawLines~ParseLineContext} context The context
 * @property {number} rawArgumentsIndex The current arguments index that point to -g
 * @property {number} rawArgumentsLength The raw argument length
 */
/**
 * Parse a raw command
 * @param {IptablesSaveParser._parseRawGotoCommand~Options} options The options
 * @return {Promise} {@link IptablesSaveParser._parseRawGotoCommand~OnResolve} on resolve
 */
IptablesSaveParser.prototype._parseRawGotoCommand = function (options) {

  return new Promise(resolve => {
    options.context.command.arguments.goto = {
      chainName: options.context.command.rawArguments[options.rawArgumentsIndex + 1]
    };
    // Must be the last one
    return resolve({
      newArgumentsIndex: options.rawArgumentsLength
    });
  });
};


/**
 * @typedef {Object} IptablesSaveRawCommandMatchParser
 * @property {Function} parse The parse function
 */

/**
 * @typedef {Object} IptablesSaveParser._parseRawMatchCommand~OnResolve
 * @property {number} newArgumentsIndex The new index to set
 */
/**
 * @typedef {Object} IptablesSaveParser._parseRawMatchCommand~Options
 * @property {IptablesSaveParser.parseRawGotoCommand~ParseLineContext} context The context
 * @property {number} rawArgumentsIndex The current arguments index that point to -m
 * @property {number} matchLength The number of argument found for the match
 */
/**
 * Parse a raw match command
 * @param {IptablesSaveParser._parseRawMatchCommand~Options} options The options
 * @return {Promise} {@link IptablesSaveParser._parseRawMatchCommand~OnResolve} on resolve
 */
IptablesSaveParser.prototype._parseRawMatchCommand = function (options) {

  return new Promise((resolve, reject) => {
    const matchName = options.context.command.rawArguments[options.rawArgumentsIndex + 1];

    this._findRawMatchCommandParser({
      matchName: matchName
    })
      .then(findParserResponse => {
        if (findParserResponse.parser && _.isFunction(findParserResponse.parser.parse)) {
          return findParserResponse.parser.parse(options);
        }

        throw new Error(util.format("Cannot handle the match '%s'", matchName));
      })
      .then(() => {
        return resolve({
          newArgumentsIndex: options.rawArgumentsIndex + options.matchLength
        });
      })
      .catch(error => reject(error));
  });
};

/**
 * @typedef {Object} IptablesSaveParser._findRawMatchCommandParser~OnResolve
 * @property {IptablesSaveRawCommandMatchParser} parser The parser to use
 */
/**
 * @typedef {Object} IptablesSaveParser._findRawMatchCommandParser~Options
 * @property {string} matchName The match parser to found
 */
/**
 * Try to find the match command parser for the given match name
 * @param {IptablesSaveParser._findRawMatchCommandParser~Options} options The options
 * @return {Promise} {@link IptablesSaveParser._findRawMatchCommandParser~OnResolve} on resolve
 */
IptablesSaveParser.prototype._findRawMatchCommandParser = function (options) {
  return new Promise(resolve => {
    const db = {
      // udp: {
      //   parser: this.parseRawMatchCommandUdp.bind(this)
      // },
      // tcp: {
      //   parser: this.parseRawMatchCommandTcp.bind(this)
      // },
      // state: {
      //   parser: this.parseRawMatchCommandState.bind(this)
      // },
      // icmp: {
      //   parser: this.parseRawMatchCommandIcmp.bind(this)
      // },
      // owner: {
      //   parser: this.parseRawMatchCommandOwner.bind(this)
      // },
      // conntrack: {
      //   parser: this.parseRawMatchCommandConnTrack.bind(this)
      // },
      // addrtype: {
      //   parser: this.parseRawMatchCommandAddRType.bind(this)
      // }
    };

    return resolve({
      parser: db[options.matchName] ? db[options.matchName].parser : {
        parse: this._parseGenericRawMatchCommand.bind(this)
      }
    });
  });
};

/**
 * Parse a raw match command using the generic handler
 * @param {IptablesSaveParser._parseRawMatchCommand~Options} options The options
 * @return {Promise} {@link IptablesSaveParser._parseRawMatchCommand~OnResolve} on resolve
 */
IptablesSaveParser.prototype._parseGenericRawMatchCommand = function (options) {
  return new Promise(resolve => {
    const matchName = options.context.command.rawArguments[options.rawArgumentsIndex + 1],
      rawArguments = options.context.command.rawArguments;

    if (!options.context.command.arguments.matches[matchName]) {
      options.context.command.arguments.matches[matchName] = {};
    }

    const commandMatches = options.context.command.arguments.matches[matchName];

    const rawArgumentsEnd = options.rawArgumentsIndex + options.matchLength;
    let useNegation = false, currentKey;
    for (let rawArgumentsIndex = options.rawArgumentsIndex + 2; rawArgumentsIndex < rawArgumentsEnd;) {
      if (rawArguments[rawArgumentsIndex] === '!') {
        useNegation = true;
        ++rawArgumentsIndex;
        continue;
      }

      if (_.startsWith(rawArguments[rawArgumentsIndex], '--')) {
        currentKey = rawArguments[rawArgumentsIndex].substr(2);
      } else if (!currentKey) {
        currentKey = rawArguments[rawArgumentsIndex];
      } else {
        commandMatches[currentKey] = useNegation ? '!' + rawArguments[rawArgumentsIndex] : rawArguments[rawArgumentsIndex];
      }

      ++rawArgumentsIndex;
      useNegation = false;
    }

    return resolve({
      newArgumentIndex: options.rawArgumentsIndex + options.matchLength
    });
  });
};

exports.IptablesSaveParser = module.exports.IptablesSaveParser = IptablesSaveParser;
