use ckb_sdk::{
    transaction::{
        builder::{sudt::SudtTransactionBuilder, CkbTransactionBuilder},
        input::InputIterator,
        signer::{SignContexts, TransactionSigner},
        TransactionBuilderConfiguration,
    },
    Address, CkbRpcClient, NetworkInfo,
};
use ckb_types::prelude::Builder;
use ckb_types::{
    core::ScriptHashType,
    h256,
    packed::Script,
    prelude::{Entity, Pack},
    H256,
};

use std::{error::Error as StdErr, fmt::Error, str::FromStr};

fn init_udt(wallet_address: &str, key: &H256, sudt_amount: u128) -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::devnet();
    let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;

    let issuer = Address::from_str(wallet_address)?;
    let iterator = InputIterator::new_with_address(&[issuer.clone()], &network_info);
    let mut builder = SudtTransactionBuilder::new(configuration, iterator, &issuer, true)?;
    builder.add_output(&issuer, sudt_amount);

    let mut tx_with_groups = builder.build(&Default::default())?;

    let private_keys = vec![key.clone()];

    TransactionSigner::new(&network_info).sign_transaction(
        &mut tx_with_groups,
        &SignContexts::new_sighash_h256(private_keys)?,
    )?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    // let result = CkbRpcClient::new(network_info.url.as_str())
    //     .test_tx_pool_accept(json_tx.inner.clone(), None)
    //     .expect("accept transaction");
    // println!(">>> check tx result: {:?}  <<<", result);

    let tx_hash = CkbRpcClient::new(network_info.url.as_str())
        .send_transaction(json_tx.inner, None)
        .expect("send transaction");

    println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}

fn check_account(address: &str, issuer_address: &str) -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::devnet();
    let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;

    let issuer = Address::from_str(issuer_address)?;

    let sender = Address::from_str(address)?;
    let iterator = InputIterator::new_with_address(&[sender.clone()], &network_info);
    let builder = SudtTransactionBuilder::new(configuration, iterator, &issuer, false)?;

    const CKB_SHANNONS: u64 = 100_000_000;
    let (account_ckb_amount, account_udt_amount) = builder.check()?;
    eprintln!(
        "account: {:?} udt_amount: {}",
        account_ckb_amount / CKB_SHANNONS,
        account_udt_amount
    );
    Ok(())
}

fn send(
    sender_info: &(&str, H256),
    receiver: &str,
    amount: u128,
    issuer_address: Option<&str>,
) -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::devnet();
    let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;

    let issuer = if let Some(address) = issuer_address {
        Address::from_str(address)?
    } else {
        Address::from_str(sender_info.0)?
    };
    let sender = Address::from_str(sender_info.0)?;
    let receiver = Address::from_str(receiver)?;
    let iterator = InputIterator::new_with_address(&[sender.clone()], &network_info);
    let mut builder = SudtTransactionBuilder::new(configuration, iterator, &issuer, false)?;

    const CKB_SHANNONS: u64 = 100_000_000;
    let (account_ckb_amount, account_udt_amount) = builder.check()?;
    eprintln!(
        "account: {:?} udt_amount: {}",
        account_ckb_amount / CKB_SHANNONS,
        account_udt_amount
    );

    builder.add_output(&receiver, amount);

    let mut tx_with_groups = builder.build(&Default::default())?;

    let private_keys = vec![sender_info.1.clone()];
    TransactionSigner::new(&network_info).sign_transaction(
        &mut tx_with_groups,
        &SignContexts::new_sighash_h256(private_keys)?,
    )?;

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    eprintln!(
        "final tx: {}",
        serde_json::to_string_pretty(&json_tx).unwrap()
    );

    // let result = CkbRpcClient::new(network_info.url.as_str())
    //     .test_tx_pool_accept(json_tx.inner.clone(), None)
    //     .expect("accept transaction");
    // println!(">>> tx result: {:?}  <<<", result);

    let tx_hash = CkbRpcClient::new(network_info.url.as_str())
        .send_transaction(json_tx.inner, None)
        .expect("send transaction");
    println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}

fn generate_blocks(num: u64) -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::devnet();
    let rpc_client = CkbRpcClient::new(network_info.url.as_str());
    for i in 0..num {
        rpc_client.generate_block()?;
        // sleep 1s
        std::thread::sleep(std::time::Duration::from_secs(1));
        eprintln!("block generated: {}", i);
    }
    Ok(())
}

fn generate_udt_type_script(address: &str) -> ckb_types::packed::Script {
    let address = Address::from_str(address).expect("parse address");
    let sudt_owner_lock_script: Script = (&address).into();

    let code_hash = h256!("0xe1e354d6d643ad42724d40967e334984534e0367405c5ae42a9d7d63d77df419");
    let res = Script::new_builder()
        .code_hash(code_hash.pack())
        .hash_type(ScriptHashType::Data1.into())
        .args(sudt_owner_lock_script.calc_script_hash().as_bytes().pack())
        .build();
    res
}

#[allow(dead_code)]
fn parse_u128(data: &[u8]) -> Result<u128, Error> {
    let data_bytes: Vec<u8> = data.into();
    let amount = u128::from_le_bytes(data_bytes.try_into().unwrap());
    eprintln!("amount: {:?}", amount);
    return Ok(amount);
}

fn init() -> Result<(), Box<dyn StdErr>> {
    // The address is from
    // ckb-cli account import --local-only --privkey-path tests/nodes/deployer/ckb-chain/key
    let udt_owner = ("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqwgx292hnvmn68xf779vmzrshpmm6epn4c0cgwga", h256!("0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc"));

    let script = generate_udt_type_script(udt_owner.0);
    println!("udt_type_script: {:?}", script);

    let wallets = [
        ("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqgx5lf4pczpamsfam48evs0c8nvwqqa59qapt46f", h256!("0xcccd5f7e693b60447623fb71a5983f15a426938c33699b1a81d1239cfa656cd1")),
        ("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqt4vqqyehpxn47deg5l6eeqtkfrt5kfkfchkwv62", h256!("0x85af6ff21ea891dbb384b771e02317427e7b66e84b4516c03d74ca4fd5ad0500")),
        ("ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqtrnd9f2lh5vlwlj23dedf7jje65cdj8qs7q4awr", h256!("0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb975ffffff")),
    ];

    init_udt(udt_owner.0, &udt_owner.1, 800000000000).expect("init udt");
    generate_blocks(4).expect("ok");

    send(&udt_owner, wallets[0].0, 200000000000, Some(udt_owner.0))?;
    generate_blocks(4).expect("ok");

    send(&udt_owner, wallets[1].0, 200000000000, Some(udt_owner.0))?;
    generate_blocks(4).expect("ok");

    send(&udt_owner, wallets[2].0, 200000000000, Some(udt_owner.0))?;
    generate_blocks(4).expect("ok");

    // send(&wallets[0], wallets[1].0, 200000000000, Some(udt_owner.0))?;
    // generate_blocks(4).expect("ok");

    check_account(udt_owner.0, udt_owner.0)?;
    check_account(wallets[0].0, udt_owner.0)?;
    check_account(wallets[1].0, udt_owner.0)?;
    check_account(wallets[2].0, udt_owner.0)?;

    Ok(())
}

fn main() {
    init().expect("init");
}
