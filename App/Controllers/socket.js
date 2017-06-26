let InsightApiRepository = require("../Repositories/InsightApiRepository"),
    HistoryService = require("../Services/HistoryService"),
    MobileContractBalanceNotifier = require("../Components/MobileContractBalanceNotifier"),
    MobileAddressBalanceNotifier = require("../Components/MobileAddressBalanceNotifier"),
    logger = require('log4js').getLogger('Socket Controller'),
    config = require('../../config/main.json'),
    socketIO = require('socket.io'),
    socketIOClient = require('socket.io-client');

const Address = require('../Components/Address');
const _ = require('lodash');
const TokenBalanceChangeEvents = require('../Components/SocketEvents/TokenBalanceChangeEvents');
const QtumRoomEvents = require('../Components/SocketEvents/QtumRoomEvents');
const ContractBalance = require('../Components/ContractBalance');

let Controllers = getControllers();

class SocketController {

    constructor() {
        logger.info('Init');
        this.socket = null;
        this.socketClient = null;
        this.events = {};
    }

    init(server) {

        this.contractBalanceComponent = new ContractBalance();
        this.mobileContractBalanceNotifier = new MobileContractBalanceNotifier(this.contractBalanceComponent);

        this.initSocket(server);
        this.initRemoteSocket(config.INSIGHT_API_SOCKET_SERVER);
        this.initSocketEvents();

        this.mobileAddressBalanceNotifier = new MobileAddressBalanceNotifier(this.socketClient);

    }

    initSocket(server) {
        this.socket = socketIO.listen(server);
        this.socket.on('connection', this.socketHandler.bind(this));
    }

    initRemoteSocket(SOCKET_SERVER) {
        this.socketClient = socketIOClient(SOCKET_SERVER);
    }

    initSocketEvents() {
        this.events.tokenBalanceEvents = new TokenBalanceChangeEvents(this.socket, this.contractBalanceComponent);
        this.events.qtumRoomEvents = new QtumRoomEvents(this.socket, this.socketClient);
    }

    /**
     * @param {Object} socket - Socket emitter
     *
     */
    socketHandler(socket) {

        let remoteAddress = this._getRemoteAddress(socket);

        logger.info('a user connected', remoteAddress);

        socket.on('subscribe', (name, payload, options) => {

            logger.info(remoteAddress, 'Web socket subscribe:', name, payload, options);

            switch (name) {
                case 'balance_subscribe':

                    this.subscribe_balance_change(payload, this.getMergedBaseConfig(options));

                    break;
                case 'token_balance_change':

                    this.subscribe_token_balance_change(payload, this.getMergedBaseConfig(options));

                    break;
            }

        });

        socket.on('unsubscribe', (name, payload, options) => {

            logger.info(remoteAddress, 'Web socket unsubscribe:', name);

            switch (name) {
                case 'balance_subscribe':

                    this.unsubscribe_balance(payload, this.getMergedBaseConfig(options));

                    break;

                case 'token_balance_change':

                    this.unsubscribe_token_balance(payload, this.getMergedBaseConfig(options));

                    break;
            }

        });

        socket.on('disconnect', () => {

            this.events.qtumRoomEvents.unsubscribeAddress(socket, null);
            this.events.tokenBalanceEvents.unsubscribeAddress(socket, null);

            logger.info('User disconnected', remoteAddress);

        });

    }

    /**
     *
     * @param options
     * @returns {{notificationToken: String|null, prevToken: String|null, language: String}}
     */
    getMergedBaseConfig(options) {

        if (!options) {
            options = {};
        }

        let language = 'en';

        if (['es', 'en', 'cn', 'de'].indexOf(options.language) !== -1) {
            language = options.language;
        }

        return {
            notificationToken: options.notificationToken || null,
            prevToken: options.prevToken || null,
            language: language
        };
    }

    /**
     *
     * @param {Array} addresses
     * @param {Object} options
     * @returns {boolean}
     */
    subscribe_balance_change(addresses, options) {

        if (!this.addressesIsValid(addresses)) {
            return false;
        }

        this.events.qtumRoomEvents.subscribeAddress(this.socket, addresses);

        if (options.notificationToken) {
            this.mobileAddressBalanceNotifier.subscribeAddress(addresses, options);
        }
    }

    /**
     *
     * @param {Object} payload
     * @param {Object} options
     * @returns {boolean}
     */
    subscribe_token_balance_change(payload, options) {

        if (!_.isObject(payload) || !payload.contract_address || !_.isString(payload.contract_address) || !payload.addresses) {
            return false;
        }

        let addresses = payload.addresses,
            contractAddress = payload.contract_address;

        if (!this.addressesIsValid(addresses)) {
            return false;
        }

        this.events.tokenBalanceEvents.subscribeAddress(this.socket, payload);

        if (options.notificationToken && addresses.length) {
            this.mobileContractBalanceNotifier.subscribeMobileTokenBalance(contractAddress, addresses, options);
        }

    }

    /**
     *
     * @param {Array|null} addresses
     * @param {Object|null} options
     * @param {String} options.notificationToken
     * @returns {boolean}
     */
    unsubscribe_balance(addresses, options) {

        if (!_.isNull(addresses) && !this.addressesIsValid(addresses)) {
            return false;
        }

        this.events.qtumRoomEvents.unsubscribeAddress(this.socket, addresses);

        if (options.notificationToken) {
            this.mobileAddressBalanceNotifier.unsubscribeAddress(options.notificationToken, addresses);
        }

    }

    /**
     *
     * @param {*} payload
     * @param options
     */
    unsubscribe_token_balance(payload, options) {
        this.events.tokenBalanceEvents.unsubscribeAddress(this.socket, payload);

        if (options.notificationToken) {
            this.mobileContractBalanceNotifier.unsubscribeMobileTokenBalance(options.notificationToken, payload && payload.contract_address ? payload.contract_address : null, payload && payload.addresses ? payload.addresses : null, () => {});
        }
    }

    /**
     *
     * @param {*} addresses
     * @returns {boolean}
     */
    addressesIsValid(addresses) {

        if (!_.isArray(addresses)) {
            return false;
        }

        if (!addresses.length) {
            return false;
        }

        let invalidAddress = addresses.find((address) => {
            return !Address.isValid(address, config.NETWORK);
        });

        return !invalidAddress;

    }

    /**
     *
     * @param {Object} socket - Socket emitter
     * @returns {*}
     * @private
     */
    _getRemoteAddress(socket) {
        return socket.client.request.headers['cf-connecting-ip'] || socket.conn.remoteAddress;
    };
}

Controllers.socket = new SocketController();