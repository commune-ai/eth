// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Import OpenZeppelin Contracts
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract LiquidityPoolToken is ERC20, AccessControl {
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    // Mapping to keep track of stakes
    mapping(address => uint256) public stakes;
    uint256 public totalStaked;

    // Fee percentages (with 2 decimals, e.g., 1000 = 10.00%)
    uint256 public holderFeePercentage = 9000; // 90% to holders
    uint256 public managerFeePercentage = 1000; // 10% to manager

    // Consensus parameters
    uint256 public proposalId;
    struct Proposal {
        address proposer;
        uint256 newHolderFeePercentage;
        uint256 newManagerFeePercentage;
        uint256 approvals;
        uint256 deadline;
    }
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public voted;

    event TokensStaked(address indexed staker, uint256 amount);
    event TokensUnstaked(address indexed staker, uint256 amount);
    event FeesDistributed(uint256 amount);
    event ProposalCreated(uint256 proposalId, address proposer);
    event ProposalApproved(uint256 proposalId, address approver);

    constructor() ERC20("LiquidityPoolToken", "LPT") {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(MANAGER_ROLE, msg.sender);
    }

    // Stake Tokens
    function stakeTokens(uint256 amount) external {
        require(amount > 0, "Cannot stake zero tokens");
        _transfer(msg.sender, address(this), amount);
        stakes[msg.sender] += amount;
        totalStaked += amount;
        emit TokensStaked(msg.sender, amount);
    }

    // Unstake Tokens
    function unstakeTokens(uint256 amount) external {
        require(stakes[msg.sender] >= amount, "Not enough staked");
        stakes[msg.sender] -= amount;
        totalStaked -= amount;
        _transfer(address(this), msg.sender, amount);
        emit TokensUnstaked(msg.sender, amount);
    }

    // Distribute Fees
    function distributeFees() external {
        uint256 contractBalance = balanceOf(address(this)) - totalStaked;
        require(contractBalance > 0, "No fees to distribute");

        uint256 holderShare = (contractBalance * holderFeePercentage) / 10000;
        uint256 managerShare = (contractBalance * managerFeePercentage) / 10000;

        // Distribute to manager
        _transfer(address(this), getRoleMember(MANAGER_ROLE, 0), managerShare);

        // Distribute to holders
        for (uint256 i = 0; i < totalStaked; i++) {
            address staker = getStakerByIndex(i);
            uint256 reward = (holderShare * stakes[staker]) / totalStaked;
            _transfer(address(this), staker, reward);
        }

        emit FeesDistributed(contractBalance);
    }

    // Propose Fee Changes (Preventing Self-Voting)
    function proposeFeeChange(uint256 newHolderFee, uint256 newManagerFee) external {
        require(hasRole(MANAGER_ROLE, msg.sender), "Only manager can propose");
        proposalId++;
        proposals[proposalId] = Proposal({
            proposer: msg.sender,
            newHolderFeePercentage: newHolderFee,
            newManagerFeePercentage: newManagerFee,
            approvals: 0,
            deadline: block.timestamp + 3 days  // Voting period
        });
        emit ProposalCreated(proposalId, msg.sender);
    }

    // Approve Proposal
    function approveProposal(uint256 _proposalId) external {
        Proposal storage proposal = proposals[_proposalId];
        require(block.timestamp < proposal.deadline, "Proposal expired");
        require(!voted[_proposalId][msg.sender], "Already voted");
        require(stakes[msg.sender] > 0, "Must be a staker to vote");

        voted[_proposalId][msg.sender] = true;
        proposal.approvals += stakes[msg.sender];

        emit ProposalApproved(_proposalId, msg.sender);

        // If majority approval reached, execute changes
        if (proposal.approvals > totalStaked / 2) {
            holderFeePercentage = proposal.newHolderFeePercentage;
            managerFeePercentage = proposal.newManagerFeePercentage;
            // Delete proposal to prevent re-use
            delete proposals[_proposalId];
        }
    }

    // Helper function to get staker by index (not practical for large numbers of stakers)
    function getStakerByIndex(uint256 index) internal view returns (address) {
        // Implementation depends on how you store stakers
        // For a production contract, you'd need a more scalable method
    }
}