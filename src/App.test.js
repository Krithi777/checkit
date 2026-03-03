import { render, screen } from '@testing-library/react';
import App from './App';

test('renders password analyzer', () => {
  render(<App />);
  const heading = screen.getByText(/Password Fortress/i);
  expect(heading).toBeInTheDocument();
});
