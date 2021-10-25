#include <wraptoken.hpp>

namespace eosio {


//fetches proof from the bridge contract
token::validproof token::get_proof(const uint64_t proof_id){

  auto p = _proofstable.find(proof_id);

  check(p != _proofstable.end(), "proof not found");

  return *p;

}


//adds a proof to the list of processed proofs (throws an exception if proof already exists)
void token::add_or_assert(const validproof& proof, const name& payer){

    auto pid_index = _processedtable.get_index<"digest"_n>();

    auto p_itr = pid_index.find(proof.receipt_digest);

    check(p_itr == pid_index.end(), "action already proved");

    _processedtable.emplace( payer, [&]( auto& s ) {
        s.id = _processedtable.available_primary_key();
        s.receipt_digest = proof.receipt_digest;
    });

}

void token::init(const checksum256& chain_id, const name& token_contract, const checksum256& paired_chain_id, const name& paired_wraptoken_contract)
{
    require_auth( _self );

    auto global = global_config.get_or_create(_self, globalrow);
    global.chain_id = chain_id;
    global.token_contract = token_contract;
    global.paired_chain_id = paired_chain_id;
    global.paired_wraptoken_contract = paired_wraptoken_contract;
    global_config.set(global, _self);

}

//creates a new wrapped token, requires a proof of create action
void token::create(const name& caller, const uint64_t proof_id, const asset&  maximum_supply )
{
    require_auth( caller );

    auto sym = maximum_supply.symbol;
    check( sym.is_valid(), "invalid symbol name" );
    check( maximum_supply.is_valid(), "invalid supply");
    check( maximum_supply.amount > 0, "max-supply must be positive");

    stats statstable( get_self(), sym.code().raw() );
    auto existing = statstable.find( sym.code().raw() );
    check( existing == statstable.end(), "token with symbol already exists" );

    token::validproof proof = get_proof(proof_id);

    add_or_assert(proof, caller);

    token::st_create create_act = unpack<token::st_create>(proof.action.data);

    // auto global = global_config.get();
    // check(proof.chain_id == global.paired_chain_id, "proof chain does not match paired chain");
    // check(proof.action.account == global.paired_wraptoken_contract, "proof account does not match paired account");

    check(maximum_supply.symbol.precision() == create_act.maximum_supply.symbol.precision(), "maximum_supply must use same precision");
    check(maximum_supply.amount == create_act.maximum_supply.amount, "maximum_supply must be of the same amount");

    statstable.emplace( get_self(), [&]( auto& s ) {
       s.source_chain_id = proof.chain_id;
       s.source_contract = proof.action.account;
       s.source_symbol = create_act.maximum_supply.symbol.code();
       s.supply = asset(0, maximum_supply.symbol);
       s.max_supply    = maximum_supply;
       s.issuer        = get_self();
    });


}

//Issue mints the wrapped token, requires a proof of the lock action
void token::issue(const name& caller, const uint64_t proof_id)
{
    
    token::validproof proof = get_proof(proof_id);
    
    token::xfer lock_act = unpack<token::xfer>(proof.action.data);

    auto global = global_config.get();
    check(proof.chain_id == global.paired_chain_id, "proof chain does not match paired chain");
    check(proof.action.account == global.paired_wraptoken_contract, "proof account does not match paired account");
   
    require_auth(caller);

    add_or_assert(proof, caller);

    auto sym = lock_act.quantity.quantity.symbol;
    check( sym.is_valid(), "invalid symbol name" );
    //check( memo.size() <= 256, "memo has more than 256 bytes" );

    stats statstable( get_self(), sym.code().raw() );
    auto existing = statstable.find( sym.code().raw() );
    
    check( existing != statstable.end(), "token with symbol does not exist, create token before issue" );

    check(proof.action.name == "emitxfer"_n, "must provide proof of token locking before issuing");

    const auto& st = *existing;
    //check( to == st.issuer, "tokens can only be issued to issuer account" );

    //require_auth( st.issuer );
    check( lock_act.quantity.quantity.is_valid(), "invalid quantity" );
    check( lock_act.quantity.quantity.amount > 0, "must issue positive quantity" );

    check( lock_act.quantity.quantity.symbol == st.supply.symbol, "symbol precision mismatch" );
    check( lock_act.quantity.quantity.amount <= st.max_supply.amount - st.supply.amount, "quantity exceeds available supply");

    statstable.modify( st, same_payer, [&]( auto& s ) {
       s.supply += lock_act.quantity.quantity;
    });

    add_internal_balance( lock_act.beneficiary, lock_act.quantity.quantity, lock_act.beneficiary );
    
}

//locks a token amount in the reserve for an interchain transfer
void token::lock(const name& owner,  const extended_asset& quantity, const name& beneficiary){

  require_auth(owner);

  check(quantity.contract != _self, "cannot lock wrapped tokens");


  sub_external_balance( owner, quantity );
  add_reserve( quantity );

  token::xfer x = {
    .owner = owner,
    .quantity = quantity,
    .beneficiary = beneficiary
  };

  action act(
    permission_level{_self, "active"_n},
    _self, "emitxfer"_n,
    std::make_tuple(x)
  );
  act.send();

}

//emits an xfer receipt to serve as proof in interchain transfers
void token::emitxfer(const token::xfer& xfer){
 
 require_auth(_self);

}

void token::retire(const name& owner,  const asset& quantity, const name& beneficiary)
{
    require_auth( owner );

    auto sym = quantity.symbol;
    check( sym.is_valid(), "invalid symbol name" );

    stats statstable( get_self(), sym.code().raw() );
    auto existing = statstable.find( sym.code().raw() );
    check( existing != statstable.end(), "token with symbol does not exist" );
    const auto& st = *existing;

    check( quantity.is_valid(), "invalid quantity" );
    check( quantity.amount > 0, "must retire positive quantity" );

    check( quantity.symbol == st.supply.symbol, "symbol precision mismatch" );

    statstable.modify( st, same_payer, [&]( auto& s ) {
       s.supply -= quantity;
    });

    sub_internal_balance( owner, quantity );

    token::xfer x = {
      .owner = owner,
      .quantity = extended_asset(quantity, existing->source_contract),
      .beneficiary = beneficiary
    };

    action act(
      permission_level{_self, "active"_n},
      _self, "emitxfer"_n,
      std::make_tuple(x)
    );
    act.send();

}

void token::transfer( const name&    from,
                      const name&    to,
                      const asset&   quantity,
                      const string&  memo )
{
    check( from != to, "cannot transfer to self" );
    require_auth( from );
    check( is_account( to ), "to account does not exist");
    auto sym = quantity.symbol.code();
    stats statstable( get_self(), sym.raw() );
    const auto& st = statstable.get( sym.raw() );

    require_recipient( from );
    require_recipient( to );

    check( quantity.is_valid(), "invalid quantity" );
    check( quantity.amount > 0, "must transfer positive quantity" );
    check( quantity.symbol == st.supply.symbol, "symbol precision mismatch" );
    check( memo.size() <= 256, "memo has more than 256 bytes" );

    auto payer = has_auth( to ) ? to : from;

    sub_internal_balance( from, quantity );
    add_internal_balance( to, quantity, payer );
}

void token::sub_reserve( const extended_asset& value ){

   //reserves res_acnts( get_self(), _self.value );

   const auto& res = _reservestable.get( value.quantity.symbol.code().raw(), "no balance object found" );
   check( res.balance.quantity.amount >= value.quantity.amount, "overdrawn balance" );

   _reservestable.modify( res, _self, [&]( auto& a ) {
         a.balance -= value;
      });
}

void token::add_reserve(const extended_asset& value){

   //reserves res_acnts( get_self(), _self.value );

   auto res = _reservestable.find( value.quantity.symbol.code().raw() );
   if( res == _reservestable.end() ) {
      _reservestable.emplace( _self, [&]( auto& a ){
        a.balance = value;
      });
   } else {
      _reservestable.modify( res, _self, [&]( auto& a ) {
        a.balance += value;
      });
   }

}

void token::sub_external_balance( const name& owner, const extended_asset& value ){

   extaccounts from_acnts( get_self(), owner.value );

   const auto& from = from_acnts.get( value.quantity.symbol.code().raw(), "no balance object found" );
   check( from.balance.quantity.amount >= value.quantity.amount, "overdrawn balance" );

   from_acnts.modify( from, owner, [&]( auto& a ) {
         a.balance -= value;
      });
}

void token::add_external_balance( const name& owner, const extended_asset& value, const name& ram_payer ){

   extaccounts to_acnts( get_self(), owner.value );
   auto to = to_acnts.find( value.quantity.symbol.code().raw() );
   if( to == to_acnts.end() ) {
      to_acnts.emplace( ram_payer, [&]( auto& a ){
        a.balance = value;
      });
   } else {
      to_acnts.modify( to, same_payer, [&]( auto& a ) {
        a.balance += value;
      });
   }

}

void token::sub_internal_balance( const name& owner, const asset& value ){

   accounts from_acnts( get_self(), owner.value );

   const auto& from = from_acnts.get( value.symbol.code().raw(), "no balance object found" );
   check( from.balance.amount >= value.amount, "overdrawn balance" );

   from_acnts.modify( from, owner, [&]( auto& a ) {
         a.balance -= value;
      });
}

void token::add_internal_balance( const name& owner, const asset& value, const name& ram_payer ){

   accounts to_acnts( get_self(), owner.value );
   auto to = to_acnts.find( value.symbol.code().raw() );
   if( to == to_acnts.end() ) {
      to_acnts.emplace( ram_payer, [&]( auto& a ){
        a.balance = value;
      });
   } else {
      to_acnts.modify( to, same_payer, [&]( auto& a ) {
        a.balance += value;
      });
   }

}

/*void token::sub_balance( const name& owner, const asset& value ) {

   stats statstable( get_self(), value.symbol.code().raw() );
   auto existing = statstable.find( value.symbol.code().raw() );

   if (existing != statstable.end()) sub_internal_balance(owner,value);
   else sub_external_balance(owner, value);

}

void token::add_balance( const name& owner, const asset& value, const name& ram_payer )
{

   stats statstable( get_self(), value.symbol.code().raw() );
   auto existing = statstable.find( value.symbol.code().raw() );

   if (existing != statstable.end()) add_internal_balance(owner,value, ram_payer);
   else add_external_balance(owner, value, ram_payer);

}
*/
void token::open( const name& owner, const symbol& symbol, const name& ram_payer )
{
   require_auth( ram_payer );

   check( is_account( owner ), "owner account does not exist" );

   auto global = global_config.get();
   add_external_balance(owner, extended_asset(asset{0, symbol}, global.token_contract), ram_payer);

}

void token::close( const name& owner, const symbol& symbol )
{
   require_auth( owner );

   extaccounts to_acnts( get_self(), owner.value );
   auto to = to_acnts.find( symbol.code().raw() );

   check( to != to_acnts.end(), "Balance row already deleted or never existed. Action won't have any effect." );
   check( to->balance.quantity.amount == 0, "Cannot close because the balance is not zero." );
   to_acnts.erase( to );
}

void token::deposit(name from, name to, asset quantity, string memo)
{ 

    print("transfer ", name{from}, " ",  name{to}, " ", quantity, "\n");
    print("sender: ", get_sender(), "\n");
    
    auto global = global_config.get();
    check(get_sender() == global.token_contract, "transfer not permitted from unauthorised token contract");

    extended_asset xquantity = extended_asset(quantity, global.token_contract);

    //if incoming transfer
    if (from == "eosio.stake"_n) return ; //ignore unstaking transfers
    else if (to == get_self() && from != get_self()){
      //ignore outbound transfers from this contract, as well as inbound transfers of tokens internal to this contract
      //otherwise, means it's a deposit of external token from user
      add_external_balance(from, xquantity, from);

    }

}

//withdraw tokens (requires a proof of redemption)
void token::withdraw(const name& caller, const uint64_t proof_id){

    // todo - add ability to withdraw without proof_id, or move that into unlock

    require_auth( caller );

    token::validproof proof = get_proof(proof_id);

    token::xfer redeem_act = unpack<token::xfer>(proof.action.data);

    auto global = global_config.get();
    check(proof.chain_id == global.paired_chain_id, "proof chain does not match paired chain");
    check(proof.action.account == global.paired_wraptoken_contract, "proof account does not match paired account");
   
    add_or_assert(proof, caller);

    check(proof.action.name == "emitxfer"_n, "must provide proof of token retiring before issuing");

    sub_reserve(redeem_act.quantity);
    
    action act(
      permission_level{_self, "active"_n},
      redeem_act.quantity.contract, "transfer"_n,
      std::make_tuple(_self, redeem_act.beneficiary, redeem_act.quantity.quantity, ""_n )
    );
    act.send();

}

void token::test()
{ 

  print("test", "\n");

}

void token::clear()
{ 

  // todo - tidy this so all data is cleared (iterate over scopes)

  // if (global_config.exists()) global_config.remove();

  accounts a_table( get_self(), "genesis11111"_n.value);
  extaccounts e_table( get_self(), "genesis11111"_n.value);

  stats s1_table( get_self(), symbol_code("UTX").raw());
  stats s2_table( get_self(), symbol_code("OOO").raw());

  while (s1_table.begin() != s1_table.end()) {
    auto itr = s1_table.end();
    itr--;
    s1_table.erase(itr);
  }

  while (s2_table.begin() != s2_table.end()) {
    auto itr = s2_table.end();
    itr--;
    s2_table.erase(itr);
  }

  while (a_table.begin() != a_table.end()) {
    auto itr = a_table.end();
    itr--;
    a_table.erase(itr);
  }

  while (e_table.begin() != e_table.end()) {
    auto itr = e_table.end();
    itr--;
    e_table.erase(itr);
  }

  while (_reservestable.begin() != _reservestable.end()) {
    auto itr = _reservestable.end();
    itr--;
    _reservestable.erase(itr);
  }

  while (_proofstable.begin() != _proofstable.end()) {
    auto itr = _proofstable.end();
    itr--;
    _proofstable.erase(itr);
  }

  while (_proofstable.begin() != _proofstable.end()) {
    auto itr = _proofstable.end();
    itr--;
    _proofstable.erase(itr);
  }

/*
accounts

proofstable

stats
*/
}

} /// namespace eosio

