// SPDX-License-Identifier: GPL-3.0
//This file contains two smart contracts:
//1. objDir: holds the list of advertised objectDescription
//2. SC_phi: Object Access Control Smart Contract

pragma solidity ^0.8.0;

contract objDir {

    struct Resource {
        bytes32 objectId;
        address owner;
        string objectDescription;
        string[] attributeList;
        string[] operationList;
        string[] valueList;
        string policy_description;
        address SC_phi;
    }

    uint public gasUsed_generatePolicy;
    uint public gasUsed_registerPolicy;
    uint public gasUsed_updateObject;
    uint public gasUsed_deleteObject;

    mapping (bytes32 => Resource) public resources;
    address[] public deployedContracts;
    address public ContractOwner;

    constructor (){
        ContractOwner = msg.sender;
    }
    // Sample input: ["age", "country", "role"], [">", "=", "="], ["20", "USA", "admin"]
    function generatePolicy(string[] memory _requiredAttributes, string[] memory _requiredOperations, string[] memory _requiredValues) public returns (address) {
        uint gasBefore = gasleft();
        address policyEvaluatorContract = address(new SC_phi(_requiredAttributes, _requiredOperations, _requiredValues));
        uint gasAfter = gasleft();
        gasUsed_generatePolicy = gasBefore - gasAfter;
        deployedContracts.push(policyEvaluatorContract);
        return policyEvaluatorContract;
    }

    //registerObject function allows the owner of the resource to create a new resource by using resourceId
    //sample input (format): object ID, [required attributes], [attribute values]
    //  "cartoon movie", ["age", "country", "role"], [">", "=", "="], ["20", "USA", "admin"], 0x6305CdCd11C0dE34Fe5092EB83C8507F40581eD1
    function registerPolicy(string memory _resourceDescription, string[] memory attributeKey, string[] memory _relation, string[] memory attributeValue, address _objACC) public {
        uint gasBefore = gasleft();
        require(attributeKey.length == attributeValue.length, "Number of keys and values do not match");
        require(attributeKey.length == _relation.length, "Number of keys and relations do not match");
        bytes32 resourceId = keccak256(abi.encodePacked(_resourceDescription));
        require(resources[resourceId].owner == address(0), "Resource already exists");
        resources[resourceId].objectId = resourceId;
        resources[resourceId].owner = msg.sender;
        resources[resourceId].objectDescription = _resourceDescription;
        resources[resourceId].attributeList = attributeKey;
        resources[resourceId].operationList = _relation;
        resources[resourceId].valueList = attributeValue;
        resources[resourceId].SC_phi = _objACC;
        resources[resourceId].policy_description = concatenateStringArray(attributeKey, _relation, attributeValue);
        uint gasAfter = gasleft();
        gasUsed_registerPolicy = gasBefore - gasAfter;
    }

    function viewObjectPolicy (bytes32 _objId) public view returns (string memory, address){
        return (resources[_objId].policy_description, resources[_objId].SC_phi);
    }

    function getObjectPolicyInformation (bytes32 _objId) public view returns (string[] memory, string[] memory, string[] memory){
        return (resources[_objId].attributeList, resources[_objId].operationList, resources[_objId].valueList);
    }

    function updateResource (bytes32 _oid, string memory _resourceDescription, string[] memory attributeKey, string[] memory _relation, string[] memory attributeValue, address _objACC) public{
        uint gasBefore = gasleft();
        require (resources[_oid].owner == msg.sender,"Not resource owner");
        resources[_oid].objectDescription = _resourceDescription;
        resources[_oid].attributeList = attributeKey;
        resources[_oid].operationList = _relation;
        resources[_oid].valueList = attributeValue;
        resources[_oid].SC_phi = _objACC;
        uint gasAfter = gasleft();
        gasUsed_updateObject = gasBefore - gasAfter;
    }


    function deleteResource (bytes32 _oid) public{
        uint gasBefore = gasleft();
        require (msg.sender == resources[_oid].owner || msg.sender == ContractOwner,"Not authorized user");
        delete resources[_oid];
        uint gasAfter = gasleft();
        gasUsed_deleteObject = gasBefore - gasAfter;
    }

     function concatenateStringArray(string[] memory str1, string[] memory str2, string[] memory str3) public pure returns (string memory) {
        string memory PolicyDescription = "";
        for(uint i=0; i< str1.length; i++){
            if (i == 0){
                PolicyDescription = string(abi.encodePacked(PolicyDescription, str1[i], str2[i], str3[i]));
            }
            else{
                PolicyDescription = string(abi.encodePacked(PolicyDescription, " AND ", str1[i], str2[i], str3[i]));
            }

        }

        return PolicyDescription;
    }



}

//Object Access Control Smart Contract

contract SC_phi{
    string[] public attributesNeeded;
    string[] public operationRequired;
    string[] public attributesValues;
    mapping(bytes32 => bool) grantObjectAccess;

    struct Token {
        bytes32 objectId;
        address tokenIssuer;
        address userAddress;
        bool hasAccess;
    }
    event ObjectRequestToken(Token accessToken);

    constructor(string[] memory _requiredAttributes,string[] memory _operation, string[] memory _attributeValue ) {
        attributesNeeded = _requiredAttributes;
        operationRequired = _operation;
        attributesValues = _attributeValue;
    }


    function requestObjAccess(bytes32 _objID, string[] memory _attributeKey, string[] memory _attributeValue) public {
        address _requester = msg.sender;

        grantObjectAccess[_objID] = evaluatePolicy(_attributeKey, _attributeValue);
        address policyEvaluatorContractAddress = address(this);
        // new access token
        Token memory accessToken = Token({
            objectId: _objID,
            tokenIssuer: policyEvaluatorContractAddress,
            userAddress: _requester,
            hasAccess: grantObjectAccess[_objID]
        });
        emit ObjectRequestToken(accessToken);
    }

    function evaluatePolicy(string[] memory Req_attributeKeys, string[] memory Req_attributeValues) public view returns (bool) {
        require(Req_attributeKeys.length == Req_attributeValues.length, "Number of keys and values do not match");
        bool isValid;
        for (uint i = 0; i < Req_attributeKeys.length; i++) {
            isValid = compareStrings(attributesValues[i], Req_attributeValues[i], operationRequired[i]);
            if (isValid == false){
                return false;
            }
        }
        return isValid;
    }

    function compareStrings(string memory a, string memory b, string memory op) public pure returns(bool) {
        if (keccak256(abi.encodePacked(op)) == keccak256(abi.encodePacked(">"))) {
            return (keccak256(abi.encodePacked(a)) > keccak256(abi.encodePacked(b)));
        } else if (keccak256(abi.encodePacked(op)) == keccak256(abi.encodePacked("<"))) {
            return (keccak256(abi.encodePacked(a)) < keccak256(abi.encodePacked(b)));
        } else if (keccak256(abi.encodePacked(op)) == keccak256(abi.encodePacked("="))) {
            return (keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b)));
        } else {
            revert("Invalid operator");
        }
    }

}
