import { useState, useEffect, useRef } from 'react';

// Refactor note: extracted from App.jsx. The previous implementation put
// lastScrollY in useState, which re-subscribed the scroll listener on every
// scroll event (lastScrollY was in the effect deps array). Using useRef
// avoids the re-subscription while preserving the same show/hide behavior.
export function useScrollNavbar() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isVisible, setIsVisible] = useState(true);
  const lastScrollYRef = useRef(0);

  useEffect(() => {
    const handleScroll = () => {
      const currentScrollY = window.scrollY;

      setIsScrolled(currentScrollY > 20);

      if (currentScrollY > lastScrollYRef.current && currentScrollY > 100) {
        setIsVisible(false);
      } else {
        setIsVisible(true);
      }

      lastScrollYRef.current = currentScrollY;
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return { isScrolled, isVisible };
}
