// SPDX-License-Identifier: Apache2.0
pragma solidity 0.8.4;

library IterableAddressDelegateMapping {
    struct Map {
        address[] keys;
        mapping(address => uint256) values;
        mapping(address => uint) indexOf;
    }

    function get(Map storage map, address key) internal view returns (uint256) {
        return map.values[key];
    }

    function getKeyAtIndex(Map storage map, uint index) internal view returns (address) {
        return map.keys[index];
    }

    function size(Map storage map) internal view returns (uint) {
        return map.keys.length;
    }


    function add(Map storage map, address key, uint256 val) internal {
        if (map.indexOf[key] != 0) {
            map.values[key] += val;
        } else {
            map.values[key] = val;
            map.keys.push(key);
            map.indexOf[key] = map.keys.length;
        }
    }

    function subtract(Map storage map, address key, uint256 val) internal {
        if (map.indexOf[key] != 0) {
             map.values[key] -= val;
        } 
    }

    function remove(Map storage map, address key) internal {
        if (map.indexOf[key] == 0) {
            return;
        }

        delete map.values[key];

        uint indexPlus1 = map.indexOf[key];
        if (indexPlus1 != map.keys.length) {
            address lastKey = map.keys[map.keys.length - 1];
            map.indexOf[lastKey] = indexPlus1;
            map.keys[indexPlus1 - 1] = lastKey;
        }
        delete map.indexOf[key];
        map.keys.pop();
    }

    function exist(Map storage map, address key) view internal returns(bool) {
        return map.indexOf[key] != 0;
    } 
}