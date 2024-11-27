use crate::state::eth_logs_scraping::{LogScrapingId, LogScrapingInfo, LogScrapings};

#[test]
fn should_use_info_from_deposit_with_subaccount_when_contract_address_present() {
    const LAST_SCRAPED_BLOCK_NUMBER: u32 = 21_235_426_u32;
    const ETH_HELPER_SMART_CONTRACT: &str = "0x7574eB42cA208A4f6960ECCAfDF186D627dCC175";
    const ERC20_HELPER_SMART_CONTRACT: &str = "0x6abDA0438307733FC299e9C229FD3cc074bD8cC0";
    const DEPOSIT_WITH_SUBACCOUNT_HELPER_SMART_CONTRACT: &str =
        "0x2D39863d30716aaf2B7fFFd85Dd03Dda2BFC2E38";

    let mut scrapings = LogScrapings::new(LAST_SCRAPED_BLOCK_NUMBER.into());

    assert_eq!(
        scrapings.info(),
        LogScrapingInfo {
            last_eth_scraped_block_number: Some(LAST_SCRAPED_BLOCK_NUMBER.into()),
            last_erc20_scraped_block_number: Some(LAST_SCRAPED_BLOCK_NUMBER.into()),
            ..Default::default()
        }
    );

    scrapings
        .set_contract_address(
            LogScrapingId::EthDepositWithoutSubaccount,
            ETH_HELPER_SMART_CONTRACT.parse().unwrap(),
        )
        .unwrap();
    scrapings
        .set_contract_address(
            LogScrapingId::Erc20DepositWithoutSubaccount,
            ERC20_HELPER_SMART_CONTRACT.parse().unwrap(),
        )
        .unwrap();

    assert_eq!(
        scrapings.info(),
        LogScrapingInfo {
            eth_helper_contract_address: Some(ETH_HELPER_SMART_CONTRACT.to_string()),
            last_eth_scraped_block_number: Some(LAST_SCRAPED_BLOCK_NUMBER.into()),
            erc20_helper_contract_address: Some(ERC20_HELPER_SMART_CONTRACT.to_string()),
            last_erc20_scraped_block_number: Some(LAST_SCRAPED_BLOCK_NUMBER.into()),
        }
    );

    scrapings
        .set_contract_address(
            LogScrapingId::EthOrErc20DepositWithSubaccount,
            DEPOSIT_WITH_SUBACCOUNT_HELPER_SMART_CONTRACT
                .parse()
                .unwrap(),
        )
        .unwrap();
    scrapings.set_last_scraped_block_number(
        LogScrapingId::EthOrErc20DepositWithSubaccount,
        (LAST_SCRAPED_BLOCK_NUMBER + 1).into(),
    );

    assert_eq!(
        scrapings.info(),
        LogScrapingInfo {
            eth_helper_contract_address: Some(
                DEPOSIT_WITH_SUBACCOUNT_HELPER_SMART_CONTRACT.to_string()
            ),
            last_eth_scraped_block_number: Some((LAST_SCRAPED_BLOCK_NUMBER + 1).into()),
            erc20_helper_contract_address: Some(
                DEPOSIT_WITH_SUBACCOUNT_HELPER_SMART_CONTRACT.to_string()
            ),
            last_erc20_scraped_block_number: Some((LAST_SCRAPED_BLOCK_NUMBER + 1).into()),
        }
    );
}
