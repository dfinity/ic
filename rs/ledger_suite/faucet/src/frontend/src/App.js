import { html, render } from 'lit-html';
import { createActor } from 'declarations/testicp-backend';
import logo from './logo2.svg';
import { Principal } from '@dfinity/principal';

// Enum for ledger types
const LedgerType = {
  ICP: 'ICP',
  ICRC1: 'ICRC1'
};

class App {
  constructor() {
    // Get token symbol from environment variable, with fallback to TICRC1
    this.tokenSymbol = import.meta.env.VITE_TOKEN_SYMBOL || 'TICRC1';

    // Infer ledger type from token symbol
    if (this.tokenSymbol === 'TESTICP') {
      this.ledgerType = LedgerType.ICP;
      this.backend = createActor(process.env.CANISTER_ID_TESTICP_BACKEND);
    } else {
      this.ledgerType = LedgerType.ICRC1;
      this.backend = createActor(process.env.CANISTER_ID_TICRC1_BACKEND);
    }
    
    this.greeting = '';
    this.isLoading = false;
    this.isError = false;
    this.isSuccess = false;
    
    this.#render();
  }

  #triggerCoinAnimation() {
    // Create coins animation
    for (let i = 0; i < 15; i++) {
      setTimeout(() => {
        const coin = document.createElement('div');
        coin.className = 'coin';
        coin.innerHTML = '●';
        coin.style.left = Math.random() * 100 + '%';
        coin.style.animationDelay = Math.random() * 0.5 + 's';
        coin.style.animationDuration = (Math.random() * 1 + 2) + 's';
        document.body.appendChild(coin);
        
        // Remove coin after animation
        setTimeout(() => {
          if (coin.parentNode) {
            coin.parentNode.removeChild(coin);
          }
        }, 3000);
      }, i * 100);
    }
  }

  #handleSubmit = async (e) => {
    e.preventDefault();
    const inputValue = document.getElementById('principal').value.trim();
    
    if (!inputValue) {
      const inputType = this.ledgerType === LedgerType.ICP ? 'Account Identifier' : 'Principal ID';
      this.greeting = `Please enter a valid ${inputType}.`;
      this.isError = true;
      this.isSuccess = false;
      this.#render();
      return;
    }

    try {
      this.isLoading = true;
      this.isError = false;
      this.isSuccess = false;
      this.greeting = 'Processing your request...';
      this.#render();

      let result;
      if (this.ledgerType === LedgerType.ICRC1) {
        const principal = Principal.fromText(inputValue);
        result = await this.backend.transfer_icrc1(principal);
      } else if (this.ledgerType === LedgerType.ICP) {
        // For ICP, we pass the Account Identifier directly as string
        result = await this.backend.transfer_icp(inputValue);
      }

      this.greeting = result || `Success! 10 ${this.tokenSymbol} tokens have been transferred to your account.`;
      this.isError = false;
      this.isSuccess = true;
      this.#triggerCoinAnimation();
    } catch (error) {
      console.error(error);
      const inputType = this.ledgerType === LedgerType.ICP ? 'Account Identifier' : 'Principal ID';
      this.greeting = `Error: Invalid ${inputType} format. Please check and try again.`;
      this.isError = true;
      this.isSuccess = false;
    } finally {
      this.isLoading = false;
      this.#render();
    }
  };

  #render() {
    const inputType = this.ledgerType === LedgerType.ICP ? 'Account Identifier' : 'Principal';
    const inputPlaceholder = this.ledgerType === LedgerType.ICP 
      ? 'e.g. d4685b31b51450508aff0d02b4f023b2a7d1f74b...' 
      : 'e.g. u6s2n-gx777-77774-qaaba-cai';

    let body = html`
      <main>
        <h1>${this.tokenSymbol} Token Faucet</h1>
        <p>Get 10 ${this.tokenSymbol} test tokens for development and testing</p>
        
        <form action="#">
          <label for="principal">Enter your ${inputType}:</label>
          <input 
            id="principal" 
            alt="${inputType}" 
            type="text" 
            placeholder="${inputPlaceholder}"
            ?disabled=${this.isLoading}
          />
          <button type="submit" ?disabled=${this.isLoading}>
            ${this.isLoading ? 'Processing...' : 'Request Tokens'}
          </button>
        </form>
        
        <section id="message" class="${this.isError ? 'error' : this.isSuccess ? 'success' : ''}">${this.greeting}</section>
        
        <div class="info">
          <p><strong>Instructions:</strong></p>
          <ul>
            <li>Enter your Internet Computer ${inputType} above</li>
            <li>Click "Request Tokens" to receive 10 ${this.tokenSymbol} tokens</li>
            <li>Use these tokens for testing and development purposes</li>
          </ul>
        </div>
        
        <img src="${logo}" alt="100% onchain" />
      </main>
    `;
    render(body, document.getElementById('root'));
    document
      .querySelector('form')
      .addEventListener('submit', this.#handleSubmit);
  }
}

export default App;
