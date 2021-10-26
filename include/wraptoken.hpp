#pragma once

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>

#include <string>

namespace eosiosystem {
   class system_contract;
}

namespace eosio {

   const name bridge_contract = "andybridge1"_n;

   using std::string;

   class [[eosio::contract("wraptoken")]] token : public contract {
      private:

        struct st_create {
          name          issuer;
          asset         maximum_supply;
        };

         struct [[eosio::table]] global {
            checksum256   chain_id;
            checksum256   paired_chain_id;
            name          paired_wraplock_contract;
            name          paired_token_contract;
         } globalrow;

         struct [[eosio::table]] account {
            asset    balance;

            uint64_t primary_key()const { return balance.symbol.code().raw(); }
         };

         struct [[eosio::table]] extaccount {
            extended_asset    balance;

            uint64_t primary_key()const { return balance.quantity.symbol.code().raw(); }
         };

         struct [[eosio::table]] currency_stats {

            //uniquely identify source information
            name          source_contract;
            checksum256   source_chain_id;
            symbol_code   source_symbol;

            asset         supply;
            asset         max_supply;
            name          issuer;

            uint64_t primary_key()const { return supply.symbol.code().raw(); }
         };


         void sub_internal_balance( const name& owner, const asset& value );
         void add_internal_balance( const name& owner, const asset& value, const name& ram_payer );

      public:
         using contract::contract;

         struct [[eosio::table]] validproof {

           uint64_t                        id;
           action                          action;
           checksum256                     chain_id;
           checksum256                     receipt_digest;
           name                            prover;

           uint64_t primary_key()const { return id; }
           checksum256 by_digest()const { return receipt_digest; }

           EOSLIB_SERIALIZE( validproof, (id)(action)(chain_id)(receipt_digest)(prover))

         };

         struct [[eosio::table]] processed {

           uint64_t                        id;
           checksum256                     receipt_digest;

           uint64_t primary_key()const { return id; }
           checksum256 by_digest()const { return receipt_digest; }

           EOSLIB_SERIALIZE( processed, (id)(receipt_digest))

         };

         struct [[eosio::table]] xfer {
           name             owner;
           extended_asset   quantity;
           name             beneficiary;
         };


         [[eosio::action]]
         void init(const checksum256& chain_id, const checksum256& paired_chain_id, const name& paired_wraptoken_contract, const name& paired_token_contract);

         [[eosio::action]]
         void create(const name& caller, const uint64_t proof_id, const asset&  maximum_supply);
    
         [[eosio::action]]
         void issue(const name& caller, const uint64_t proof_id);


         [[eosio::action]]
         void retire(const name& owner,  const asset& quantity, const name& beneficiary);


         [[eosio::action]]
         void transfer( const name&    from,
                        const name&    to,
                        const asset&   quantity,
                        const string&  memo );
  
         [[eosio::action]]
         void open( const name& owner, const symbol& symbol, const name& ram_payer );


         [[eosio::action]]
         void close( const name& owner, const symbol& symbol );

         [[eosio::action]]
         void emitxfer(const token::xfer& xfer);

         [[eosio::action]]
         void clear();

         static asset get_supply( const name& token_contract_account, const symbol_code& sym_code )
         {
            stats statstable( token_contract_account, sym_code.raw() );
            const auto& st = statstable.get( sym_code.raw() );
            return st.supply;
         }

         static asset get_balance( const name& token_contract_account, const name& owner, const symbol_code& sym_code )
         {
            accounts accountstable( token_contract_account, owner.value );
            const auto& ac = accountstable.get( sym_code.raw() );
            return ac.balance;
         }


         typedef eosio::multi_index< "accounts"_n, account > accounts;
         typedef eosio::multi_index< "stat"_n, currency_stats > stats;

         typedef eosio::multi_index< "proofs"_n, validproof,
            indexed_by<"digest"_n, const_mem_fun<validproof, checksum256, &validproof::by_digest>>> proofstable;
      
         typedef eosio::multi_index< "processed"_n, processed,
            indexed_by<"digest"_n, const_mem_fun<processed, checksum256, &processed::by_digest>>> processedtable;

         using globaltable = eosio::singleton<"global"_n, global>;

         void add_or_assert(const validproof& proof, const name& prover);

         validproof get_proof(const uint64_t proof_id);

         globaltable global_config;

        proofstable _proofstable;
        processedtable _processedtable;

        token( name receiver, name code, datastream<const char*> ds ) :
        contract(receiver, code, ds),
        global_config(_self, _self.value),
        _proofstable(bridge_contract, bridge_contract.value),
        _processedtable(_self, _self.value)
        {
        
        }
        
         using create_action = eosio::action_wrapper<"create"_n, &token::create>;
         using issue_action = eosio::action_wrapper<"issue"_n, &token::issue>;
         using retire_action = eosio::action_wrapper<"retire"_n, &token::retire>;
         using transfer_action = eosio::action_wrapper<"transfer"_n, &token::transfer>;
         using open_action = eosio::action_wrapper<"open"_n, &token::open>;
         using close_action = eosio::action_wrapper<"close"_n, &token::close>;
   };

}

